package space.seclume.sqlserver.jdbc;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

import space.seclume.internal.jdbc.ResultLimit;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLWarning;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import space.seclume.sqlserver.tds.TdsParameters;
import space.seclume.sqlserver.tds.TdsSession;
import space.seclume.sqlserver.tds.TokenStream;

/**
 * A statement without parameters, as a {@code SQL_BATCH}.
 *
 * <p>While the answer is being read the rows move straight into a
 * {@link TdsResultBlock}, that is into one native block instead of objects per
 * cell. Afterwards the receive buffer is free again, and the
 * {@code ResultSet} holds nothing belonging to the session - only that way may
 * it outlive the next statement.
 */
class TdsStatement implements Statement, TokenStream.RowHandler {

    final TdsConnection connection;
    /** The connection this was made through, as the application sees it - see {@link space.seclume.internal.jdbc.Fronted}. */
    private final Connection owner;
    private TdsResultBlock block;
    private TdsResultBlock reusable;
    /** Only set while a statement is being read - see {@link #collect}. */
    private TdsResultBlock collected;
    private int collectedRows;
    /** The statement being read, for the message of a result-limit failure. */
    private String collectingSql;

    /** Where this statement was made, when the connection traces that - see OpenStatements. */
    final StackTraceElement[] createdAt;

    /** What it last ran, as text - for the fingerprint in OpenStatements. */
    String lastSql() {
        return collectingSql;
    }
    /** What the connection was configured with; ResultLimit.NONE unless set. */
    private ResultLimit resultLimit = ResultLimit.NONE;
    private TdsResultSet resultSet;
    /** Every result of the last answer, in the order the server sent them. */
    private final List<TdsResultBlock> results = new ArrayList<>(2);
    /** The blocks allocated for a second or later result - freed with the answer. */
    private final List<TdsResultBlock> owned = new ArrayList<>(2);
    private int resultIndex;
    private boolean reusableTaken;
    /** Set while a cursor fetch is running - see {@link #fetchNextBlock}. */
    private boolean refetching;
    private long updateCount = -1;
    private int maxRows;
    private int fetchSize;
    private boolean closed;
    /** {@code setQueryTimeout}, in seconds; 0 is no limit. */
    private int queryTimeout;
    private List<String> batch;

    TdsStatement(TdsConnection connection) {
        this.connection = connection;
        this.owner = connection.frontOrSelf();
        this.createdAt = connection.creationTrace();
    }

    // ---- executing -------------------------------------------------------

    @Override
    public boolean execute(String text) throws SQLException {
        String sql = escaped(text);
        underDeadline(sql, () -> executeNow(sql));
        return resultSet != null;
    }

    private void executeNow(String sql) throws SQLException {
        checkOpen();
        TdsSession session = connection.session();
        collectingSql = sql;
        collect(session, handler -> session.sqlBatch(sql, handler));
    }
    /**
     * Runs one statement under this statement's time limit.
     *
     * <p>Here rather than in each caller because every execution path needs
     * it. The wrapper starts a clock, stops it whatever happens, and turns a
     * cancellation that the clock caused into a
     * {@link java.sql.SQLTimeoutException} - see
     * {@link space.seclume.internal.jdbc.Deadline}.
     */
    final void underDeadline(String sql, Work body) throws SQLException {
        try (space.seclume.internal.jdbc.Deadline deadline =
                     space.seclume.internal.jdbc.Deadline.of(queryTimeout, this::stopNow)) {
            try {
                body.run();
            } catch (SQLException failed) {
                throw inDoubt(deadline.explain(failed), sql);
            }
            // And the statement that came back without failing: on MySQL a
            // cancelled SLEEP() succeeds, so a check only on the failure path
            // would let a timed-out statement through as a short answer.
            deadline.check();
        }
    }

    /**
     * A lost answer in auto-commit mode is a lost commit.
     *
     * <p>Every statement commits itself there, so a write whose answer never
     * arrived may have been applied - see
     * {@link space.seclume.TransactionResolutionUnknownException}. Inside a
     * transaction the same failure is not this: the server rolls an abandoned
     * transaction back, and the outcome is known.
     *
     * @param sql the statement, or {@code null} for a batch, which is always a
     *            write
     */
    final SQLException inDoubt(SQLException failure, String sql) {
        return connection.autoCommitNow()
                ? space.seclume.TransactionResolutionUnknownException.duringAutoCommit(failure, sql)
                : failure;
    }

    /** One execution, for {@link #underDeadline}. */
    @FunctionalInterface
    interface Work {
        void run() throws SQLException;
    }

    /** What the deadline runs when the time is up. */
    private void stopNow() throws SQLException {
        connection.session().cancel();
    }


    @Override
    public ResultSet executeQuery(String text) throws SQLException {
        String sql = escaped(text);
        lazyWanted = true;
        try {
            execute(sql);
        } finally {
            lazyWanted = false;
        }
        if (resultSet == null) {
            throw new SQLException("the statement returned no rows: " + shape(sql)
                    + " - use executeUpdate for statements that do not select");
        }
        return resultSet;
    }

    @Override
    public int executeUpdate(String sql) throws SQLException {
        return (int) Math.min(executeLargeUpdate(sql), Integer.MAX_VALUE);
    }

    @Override
    public long executeLargeUpdate(String text) throws SQLException {
        String sql = escaped(text);
        if (execute(sql)) {
        // JDBC requires a SQLException when the statement produced rows:
        // executeUpdate promises a count, and a caller that gets 0 back from a
        // select believes the statement ran and changed nothing. The rows are
        // closed first, because leaving a cursor open on the way out of an
        // error is how the next call on this connection finds the stream mid
        // answer.
            closeCurrentRows();
            throw new SQLException("this statement returned rows: " + shape(sql)
                    + " - use executeQuery or execute for statements that select", "0100E");
        }
        return Math.max(updateCount, 0);
    }

    /** The rows of a statement that should not have produced any. */
    private void closeCurrentRows() {
        try {
            java.sql.ResultSet rows = getResultSet();
            if (rows instanceof space.seclume.internal.jdbc.ReadOnlyResultSet own) {
                own.discard();
            } else if (rows != null) {
                rows.close();
            }
        } catch (SQLException alreadyBroken) {
            // The refusal below is the failure worth reporting.
        }
    }

    /** What the caller issues themselves - a batch or an RPC. */
    @FunctionalInterface
    interface Execution {
        TokenStream run(TokenStream.RowHandler handler) throws SQLException;
    }

    /**
     * Executes and takes the rows over along the way.
     *
     * <p>A row is a window onto the receive buffer and has to be copied out
     * before the next one is read - that is why this happens during the read
     * and not after it.
     */
    void collect(TdsSession session, Execution execution) throws SQLException {
        // Every statement this driver runs passes here. See space.seclume.jfr.
        space.seclume.jfr.Observed.Statement event =
                space.seclume.jfr.Observed.beginQuery("sqlserver");
        connection.sessionState().note(collectingSql);
        boolean failed = true;
        try {
            collectInto(session, execution);
            failed = false;
        } finally {
            space.seclume.jfr.Observed.endQuery(event, "sqlserver", collectingSql,
                    space.seclume.QueryFingerprint.Dialect.SQLSERVER,
                    block != null ? rowsCollected : Math.max(0, updateCount), failed);
        }
    }

    /** How many rows the last collect took over - for the recording. */
    private long rowsCollected;

    private void collectInto(TdsSession session, Execution execution) throws SQLException {
        if (lazy) {
            // This statement's previous answer is still paused: read it off
            // the wire - dropped - before the new one is asked for.
            discarding = true;
            try {
                session.drainPending();
            } finally {
                lazy = false;
                discarding = false;
            }
        }
        resultLimit = session.resultLimit();
        closeResult();
        // The statement is the handler itself. A lambda here would capture
        // the session, a one-element array for the block and another for the
        // counter - four objects per query, before the first row arrives.
        collected = null;
        collectedRows = 0;
        results.clear();
        resultIndex = 0;
        reusableTaken = false;
        TokenStream stream = execution.run(this);
        if (collected == null && results.isEmpty() && !stream.columns().isEmpty()) {
            // A select that found nothing and whose description arrived before
            // this statement was the handler - an empty result all the same.
            collected = blockFor(stream.columns());
        }
        finishResult();
        rowsCollected = collectedRows;
        block = results.isEmpty() ? null : results.get(0);
        lazy = block != null && session.isPaused();
        if (lazy) {
            collected = block;               // the rows still to come go here
        }
        if (capturingGeneratedKeys) {
            // The statement was sent as "<insert>;select scope_identity()", so
            // the rows that came back are the key and not a result the caller
            // asked for. The count has to come from the first statement of the
            // two: the select reports one row of its own, which for a one-row
            // insert is the same number by coincidence and not otherwise.
            closeGeneratedKeys();
            generatedKeys = block;
            block = null;
            results.clear();
            resultSet = null;
            updateCount = stream.firstUpdateCount();
            return;
        }
        resultSet = block == null ? null : new TdsResultSet(block, this);
        updateCount = block != null ? -1 : stream.updateCount();
    }

    /**
     * A new result begins - so the one being collected is complete.
     *
     * <p>This is what makes a batch or a procedure with several selects come
     * back as several results instead of one long one. The first result keeps
     * the statement's reusable block, which is the case that matters for
     * speed; every further one gets a block of its own and is freed with the
     * statement, because a second select in the same answer is rare enough
     * not to be worth a second permanent buffer.
     */
    @Override
    public void nextResult(java.util.List<space.seclume.sqlserver.tds.TdsColumn> columns) {
        if (skippingRest) {
            skippingRest = false;            // the result being dropped has ended
        } else if (discarding) {
            return;
        }
        if (lazy && collected == block) {
            // A second result behind the one that was taken while it
            // arrived: that one is in results already, the new one is not.
            collected = null;
        }
        if (refetching) {
            return;
        }
        finishResult();
        collected = blockFor(columns);
        collectedRows = 0;
    }

    /**
     * Takes the last result away from the caller's view and returns it.
     *
     * <p>{@link TdsCallableStatement} needs this: it appends a select of its
     * own to read the output parameters back, so the answer's final result is
     * the driver's own bookkeeping and not something the application asked
     * for. Removing it here is what lets the procedure's own selects be
     * handed on unchanged.
     */
    ResultSet takeLastResult() {
        if (results.isEmpty()) {
            return null;
        }
        TdsResultBlock last = results.remove(results.size() - 1);
        return new TdsResultSet(last, this);
    }

    /** Positions on the first result again, after something walked past it. */
    void positionAtFirstResult() {
        if (resultSet != null) {
            resultSet.discard();
        }
        resultIndex = 0;
        block = results.isEmpty() ? null : results.get(0);
        resultSet = block == null ? null : new TdsResultSet(block, this);
        updateCount = block == null ? updateCount : -1;
    }

    private void finishResult() {
        if (collected != null && !results.contains(collected)) {
            results.add(collected);
            collected = null;
        }
    }

    /**
     * Set while a statement carries its own {@code scope_identity()} - see
     * {@link TdsPreparedStatement}, which is the only thing that sets it.
     */
    boolean capturingGeneratedKeys;
    private TdsResultBlock generatedKeys;

    /** The key block this statement captured, or null if it captured none. */
    ResultSet capturedGeneratedKeys() {
        return generatedKeys == null ? null : new TdsResultSet(generatedKeys, this);
    }

    /**
     * Forgets the keys - without freeing anything, because the block they sit
     * in is the statement's own reusable one. {@link #blockFor} hands the same
     * memory out again for the next execution, and only {@link #close} gives
     * it back. Closing it here would free it twice.
     */
    void closeGeneratedKeys() {
        generatedKeys = null;
    }

    /**
     * Takes one row over - called from inside the protocol read, once per row.
     *
     * <p>The row is a window onto the receive buffer and is gone as soon as
     * the next one is read, so it has to be copied here and not later.
     */
    @Override
    public void row(space.seclume.sqlserver.tds.TdsRow row) throws SQLException {
        if (discarding || skippingRest) {
            return;                          // a paused answer nobody reads any more
        }
        if (collected == null) {
            collected = blockFor(row.columns());
        }
        if (maxRows == 0 || collectedRows < maxRows) {
            collected.append(row);
            collectedRows++;
            // One comparison against a field that is zero when nothing is
            // configured - and the difference between an error that names the
            // query and an OutOfMemoryError that names nothing.
            if (resultLimit.isSet()) {
                resultLimit.check(collected.bytes(), collectedRows, collectingSql);
            }
        }
    }

    ResultSet currentResultSet() {
        return resultSet;
    }

    // ---- results ---------------------------------------------------------

    @Override
    public ResultSet getResultSet() throws SQLException {
        checkOpen();
        return resultSet;
    }

    @Override
    public int getUpdateCount() throws SQLException {
        checkOpen();
        return (int) Math.min(updateCount, Integer.MAX_VALUE);
    }

    @Override
    public long getLargeUpdateCount() throws SQLException {
        checkOpen();
        return updateCount;
    }

    /**
     * Moves to the next result of the same answer.
     *
     * <p>A procedure that selects twice, or a batch of two selects, produces
     * two - and JDBC's way through them is this method. It closes the current
     * result, as the no-argument form is defined to, and says whether another
     * one followed.
     */
    @Override
    public boolean getMoreResults() throws SQLException {
        checkOpen();
        if (lazy) {
            // Whether there is another result is only known at the end of
            // the answer; the rows of this one that were not read go.
            skippingRest = true;
            try {
                connection.session().drainPending();
            } finally {
                lazy = false;
                skippingRest = false;
            }
        }
        finishResult();
        if (resultSet != null) {
            resultSet.discard();
            resultSet = null;
        }
        updateCount = -1;
        resultIndex++;
        if (resultIndex < results.size()) {
            block = results.get(resultIndex);
            resultSet = new TdsResultSet(block, this);
            return true;
        }
        block = null;
        return false;
    }

    @Override
    public boolean getMoreResults(int current) throws SQLException {
        return getMoreResults();
    }

    /**
     * Set for the length of an executeQuery: its rows may be handed out while
     * the rest of them is still arriving - see TdsSession.resume.
     */
    boolean lazyWanted;
    /** This statement's answer is paused on the session, with rows to come. */
    private boolean lazy;
    /** The paused answer is no longer wanted: what is left is read and dropped. */
    private boolean discarding;
    /** Only the rest of the current result is dropped; a later one is kept. */
    private boolean skippingRest;

    /**
     * Pause after a packet once the first result has rows - but only for a
     * plain query: not a cursor, not a statement with generated keys, not a
     * second result, and not an answer whose rows nobody will read.
     */
    @Override
    public boolean pause() {
        // The first result only: nothing in results yet on the way out of
        // executeQuery, and on a resume the one block there is the one the
        // rows go into.
        boolean first = results.isEmpty() || (lazy && results.size() == 1
                && collected == results.get(0));
        return (lazyWanted || lazy) && resultSetType == ResultSet.TYPE_FORWARD_ONLY
                && !discarding && !skippingRest && !refetching && !streaming
                && !capturingGeneratedKeys && collected != null && first
                && owned.isEmpty() && collectedRows > 0;
    }

    /** The rows of a paused answer, as far as the next pause. */
    private boolean resumeLazy() throws SQLException {
        TdsSession session = connection.session();
        if (!session.isPaused()) {
            // Read to its end already - by something else that needed the
            // connection - and those rows went into the block behind the
            // ones the result set has read.
            lazy = false;
            return false;
        }
        block.reset(block.columns());
        collected = block;
        collectedRows = 0;
        if (!session.resume()) {
            lazy = false;
        }
        return block.rowCount() > 0;
    }

    /** Whether this result is being read in blocks - see {@code setFetchSize}. */
    private boolean streaming;
    /** The handle of the open cursor, or 0. */
    private int cursor;
    /** How many rows the last block brought - fewer than asked means the end. */
    private long lastBlock;

    /**
     * Opens a server-side cursor and reads its first block.
     *
     * <p>Two round trips at the start - the open and the first fetch - and one
     * per block after that. Without a fetch size nothing of this happens.
     */
    void openCursor(TdsSession session, String sql, String declaration,
                    TdsParameters parameters) throws SQLException {
        closeResult();
        streaming = true;
        cursor = session.cursorOpen(sql, declaration, parameters);
        collected = null;
        collectedRows = 0;
        resultLimit = session.resultLimit();
        collectingSql = sql;
        lastBlock = session.cursorFetch(cursor, fetchSize, this);
        if (collected == null && !session.cursorColumns().isEmpty()) {
            collected = blockFor(session.cursorColumns());
        }
        block = collected;
        collected = null;
        resultSet = block == null ? null : new TdsResultSet(block, this);
        updateCount = -1;
    }

    /**
     * Brings the next block into the block the result set reads from.
     *
     * <p>The end is recognised by a short block: the server sends fewer rows
     * than were asked for only when there are no more.
     */
    boolean fetchNextBlock() throws SQLException {
        if (lazy) {
            return resumeLazy();
        }
        if (!streaming || block == null || cursor == 0 || lastBlock < fetchSize) {
            return false;
        }
        TdsSession session = connection.session();
        collected = block;
        collectedRows = 0;
        block.reset(block.columns());
        // A cursor fetch repeats the description before its rows. That is the
        // same result continuing, not a new one, so the boundary is ignored
        // for the length of the fetch - otherwise every block after the first
        // would start a result of its own and the rows already read would be
        // dropped.
        refetching = true;
        try {
            lastBlock = session.cursorFetch(cursor, fetchSize, this);
        } finally {
            refetching = false;
            collected = null;
        }
        return block.rowCount() > 0;
    }

    /** Gives the cursor back - a result set that was not read to the end. */
    void closeCursorIfOpen() throws SQLException {
        if (streaming && cursor != 0) {
            int handle = cursor;
            cursor = 0;
            streaming = false;
            connection.session().cursorClose(handle);
        }
    }

    /**
     * The block of this statement, ready for a new result - one per statement,
     * reused. A new one would mean a native allocation and a free per query.
     */
    private TdsResultBlock blockFor(java.util.List<space.seclume.sqlserver.tds.TdsColumn> columns) {
        if (reusableTaken) {
            // The second and any later result of one answer. Its block belongs
            // to this execution alone and goes back in closeResult.
            TdsResultBlock extra = new TdsResultBlock(columns);
            owned.add(extra);
            return extra;
        }
        reusableTaken = true;
        if (reusable == null) {
            // A block another statement of this connection left behind, if
            // there is one: allocating and freeing one per statement is the
            // most expensive thing a shared arena can be asked to do.
            reusable = connection.takeSpareBlock();
        }
        if (reusable == null) {
            reusable = new TdsResultBlock(columns);
        } else {
            reusable.reset(columns);
        }
        return reusable;
    }

    /**
     * Ends the current result - without freeing the block, which the next
     * execution reuses. The memory goes back when the statement closes.
     */
    void closeResult() {
        if (lazy) {
            // The rest of a paused answer is read and dropped, the next time
            // anything uses the connection.
            discarding = true;
        }
        if (resultSet != null) {
            resultSet.discard();
            resultSet = null;
        }
        block = null;
        results.clear();
        resultIndex = 0;
        // Only the blocks this statement allocated for a second or later
        // result. The reusable one is not among them and is freed at close.
        for (TdsResultBlock extra : owned) {
            extra.close();
        }
        owned.clear();
    }

    /**
     * The identity value just handed out.
     *
     * <p>SQL Server does not send it along, so it takes a second statement.
     * {@code scope_identity()} and not {@code @@identity}: the latter also
     * reports a value that a trigger produced in another table, which is the
     * classic source of a wrong key.
     */
    @Override
    public ResultSet getGeneratedKeys() throws SQLException {
        checkOpen();
        TdsSession session = connection.session();
        TdsStatement helper = new TdsStatement(connection);
        helper.collect(session,
                handler -> session.sqlBatch("select scope_identity() as GENERATED_KEY", handler));
        return helper.currentResultSet();
    }

    // ---- batches ---------------------------------------------------------

    @Override
    public void addBatch(String text) throws SQLException {
        String sql = escaped(text);
        checkOpen();
        if (batch == null) {
            batch = new ArrayList<>();
        }
        batch.add(sql);
    }

    @Override
    public void clearBatch() throws SQLException {
        checkOpen();
        batch = null;
    }

    @Override
    public int[] executeBatch() throws SQLException {
        long[] counts = executeLargeBatch();
        int[] small = new int[counts.length];
        for (int i = 0; i < counts.length; i++) {
            small[i] = (int) Math.min(counts[i], Integer.MAX_VALUE);
        }
        return small;
    }

    /**
     * The statements go over in one message, separated by a semicolon.
     *
     * <p>TDS allows that and it saves n-1 round trips - the point where a batch
     * of a hundred inserts stops being a hundred waits for the network. What is
     * lost is the count per statement: the server sends a DONE for each one,
     * but only the last count survives the token stream. JDBC allows
     * {@link Statement#SUCCESS_NO_INFO} for exactly this case.
     */
    @Override
    public long[] executeLargeBatch() throws SQLException {
        checkOpen();
        if (batch == null || batch.isEmpty()) {
            return new long[0];
        }
        StringBuilder text = new StringBuilder(); // seclume-allow: SQL text, never a secret
        for (String statement : batch) {
            if (!text.isEmpty()) {
                text.append(";\n");
            }
            text.append(statement);
        }
        long[] counts = new long[batch.size()];
        batch = null;
        execute(text.toString());
        java.util.Arrays.fill(counts, Statement.SUCCESS_NO_INFO);
        return counts;
    }

    // ---- settings --------------------------------------------------------

    @Override
    public int getMaxRows() {
        return maxRows;
    }

    @Override
    public void setMaxRows(int max) throws SQLException {
        if (max < 0) {
            throw new SQLException("maxRows must not be negative: " + max);
        }
        this.maxRows = max;
    }

    @Override
    public long getLargeMaxRows() {
        return maxRows;
    }

    @Override
    public void setLargeMaxRows(long max) throws SQLException {
        setMaxRows((int) Math.min(max, Integer.MAX_VALUE));
    }

    @Override
    public int getFetchSize() {
        return fetchSize;
    }

    /**
     * Accepted and remembered, but without effect: this state reads a result in
     * one go. Cursors in chunks are recorded in
     * {@code PROVENANCE.md} as an open point - a silent failure
     * would be worse here than an honest "not yet".
     */
    @Override
    public void setFetchSize(int rows) throws SQLException {
        if (rows < 0) {
            throw new SQLException("fetchSize must not be negative: " + rows);
        }
        this.fetchSize = rows;
    }

    @Override
    public int getFetchDirection() {
        return ResultSet.FETCH_FORWARD;
    }

    @Override
    public void setFetchDirection(int direction) throws SQLException {
        // A hint, as JDBC calls it: the rows come in the order the server
        // sends them whatever is hinted. Only a value that is no direction
        // at all is refused.
        space.seclume.internal.jdbc.ResultSetTypes.requireDirection(direction);
    }

    @Override
    public int getResultSetType() {
        return resultSetType;
    }

    /**
     * {@code TYPE_FORWARD_ONLY}, or {@code TYPE_SCROLL_INSENSITIVE}: then the
     * result is read whole and the cursor moves over it in any direction -
     * see {@link space.seclume.internal.jdbc.ResultSetTypes}.
     */
    private int resultSetType = ResultSet.TYPE_FORWARD_ONLY;

    void resultSetType(int type) {
        this.resultSetType = type;
    }

    /**
     * The fetch size that decides whether rows come in blocks: none for a
     * scrollable result, which has to be here whole before the cursor can
     * move back. {@link #getFetchSize} still says what was asked for.
     */
    int blockSize() {
        return resultSetType == ResultSet.TYPE_FORWARD_ONLY ? fetchSize : 0;
    }

    @Override
    public int getResultSetConcurrency() {
        return ResultSet.CONCUR_READ_ONLY;
    }

    @Override
    public int getResultSetHoldability() {
        return ResultSet.CLOSE_CURSORS_AT_COMMIT;
    }

    @Override
    public int getQueryTimeout() {
        return queryTimeout;
    }

    @Override
    public void setQueryTimeout(int seconds) throws SQLException {
        checkOpen();
        if (seconds < 0) {
            throw new SQLException("a query timeout cannot be negative: " + seconds,
                    "22023");
        }
        queryTimeout = seconds;
    }

    @Override
    public int getMaxFieldSize() throws SQLException {
        checkOpen();
        return maxFieldSize;
    }

    /** See {@link #setMaxFieldSize}; 0 for no limit. */
    private int maxFieldSize;

    /**
     * The most characters or bytes a text or binary column of this
     * statement's results hands out; the rest is dropped, as JDBC says. The
     * whole value still crosses the wire - it is cut where it is read.
     */
    @Override
    public void setMaxFieldSize(int max) throws SQLException {
        checkOpen();
        if (max < 0) {
            throw new SQLException("a maximum field size cannot be negative: " + max, "HY024");
        }
        maxFieldSize = max;
    }

    /**
     * Whether JDBC escapes in this statement's text are translated - on by
     * default, as JDBC requires. See
     * {@link space.seclume.internal.jdbc.JdbcEscapes}.
     */
    private boolean escapeProcessing = true;

    @Override
    public void setEscapeProcessing(boolean enable) throws SQLException {
        this.escapeProcessing = enable;
    }

    /** The text as the server has to see it. */
    final String escaped(String sql) {
        return escapeProcessing ? space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.SQLSERVER) : sql;
    }

    @Override
    public void cancel() throws SQLException {
        // checkOpen first: a closed statement is a SQLException, and it is the
        // ordinary outcome of the race this method is in - it is the one
        // method on this class that is called from another thread.
        checkOpen();
        connection.session().cancel();
    }

    @Override
    public void setCursorName(String name) throws SQLException {
        // JDBC: where positioned update and delete are not supported, this
        // is a no-op - and seclume has neither.
        checkOpen();
    }

    @Override
    public void setPoolable(boolean poolable) {
        // A hint, not a promise - statement caching is up to the pool.
    }

    @Override
    public boolean isPoolable() {
        return false;
    }

    @Override
    public void closeOnCompletion() throws SQLException {
        checkOpen();
        closeOnCompletion = true;
    }

    /** Set by {@link #closeOnCompletion}: the result closing closes this too. */
    private boolean closeOnCompletion;

    @Override
    public boolean isCloseOnCompletion() throws SQLException {
        checkOpen();
        return closeOnCompletion;
    }

    @Override
    public boolean execute(String sql, int autoGeneratedKeys) throws SQLException {
        return execute(sql);
    }

    @Override
    public boolean execute(String sql, int[] columnIndexes) throws SQLException {
        return execute(sql);
    }

    @Override
    public boolean execute(String sql, String[] columnNames) throws SQLException {
        return execute(sql);
    }

    @Override
    public int executeUpdate(String sql, int autoGeneratedKeys) throws SQLException {
        return executeUpdate(sql);
    }

    @Override
    public int executeUpdate(String sql, int[] columnIndexes) throws SQLException {
        return executeUpdate(sql);
    }

    @Override
    public int executeUpdate(String sql, String[] columnNames) throws SQLException {
        return executeUpdate(sql);
    }

    @Override
    public long executeLargeUpdate(String sql, int autoGeneratedKeys) throws SQLException {
        return executeUpdate(sql, autoGeneratedKeys);
    }

    @Override
    public long executeLargeUpdate(String sql, int[] columnIndexes) throws SQLException {
        return executeUpdate(sql, columnIndexes);
    }

    @Override
    public long executeLargeUpdate(String sql, String[] columnNames) throws SQLException {
        return executeUpdate(sql, columnNames);
    }

    // ---- state -----------------------------------------------------------

    @Override
    public Connection getConnection() throws SQLException {
        checkOpen();
        return owner;
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            closeResult();
            closeGeneratedKeys();
            if (reusable != null) {
                // Here, and only here, the native block goes back.
                // Not freed: the connection keeps it for the next
                // statement. See takeSpareBlock for what that is worth.
                connection.recycleBlock(reusable);
                reusable = null;
            }
            connection.forget(this);
        }
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    @Override
    public SQLWarning getWarnings() {
        return null;
    }

    @Override
    public void clearWarnings() {
        // There are no collected warnings, so there is nothing to clear.
    }

    void checkOpen() throws SQLException {
        if (closed) {
            throw new SQLException("this statement is closed");
        }
        connection.checkOpen();
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) {
            return iface.cast(this);
        }
        throw new SQLException("not a wrapper for " + iface.getName());
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) {
        return iface.isInstance(this);
    }

    /**
     * A statement named in a message, with its values taken out.
     *
     * <p>The text must not travel: a literal in it can be a password, a card
     * number or a person, and an exception message is precisely what ends up
     * in a log. The shape says which statement it was and carries none of
     * that - see {@link space.seclume.QueryFingerprint}.
     */
    private static String shape(String sql) {
        return space.seclume.QueryFingerprint.of(sql,
                space.seclume.QueryFingerprint.Dialect.SQLSERVER);
    }

}
