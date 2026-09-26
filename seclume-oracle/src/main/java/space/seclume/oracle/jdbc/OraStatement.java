package space.seclume.oracle.jdbc;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

import space.seclume.internal.jdbc.ResultLimit;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLWarning;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import space.seclume.oracle.OracleSession;
import space.seclume.oracle.net.TtcResult;

/**
 * A statement without bind variables.
 *
 * <p>While the answer is read the rows move straight into an
 * {@link OraResultBlock} - one native block instead of objects per cell. The
 * receive buffer is free again afterwards, and the {@code ResultSet} holds
 * nothing belonging to the session; only that way may it outlive the next
 * statement.
 *
 * <p>Bind variables belong to {@link OraPreparedStatement}, which runs through
 * the same path with a filled parameter list. Oracle needs no separate prepare
 * call on the wire: text and values travel in one message, so a prepared
 * statement here costs no extra round trip.
 */
class OraStatement implements Statement, TtcResult.RowHandler {

    /** ORA-00932, inconsistent data types - what a stale cursor answers. */
    private static final int STALE_DEFINE = 932;

    final OraConnection connection;
    /** The connection this was made through, as the application sees it - see {@link space.seclume.internal.jdbc.Fronted}. */
    private final Connection owner;
    private OraResultBlock block;
    private OraResultBlock reusable;
    /** Only set while a statement is being read - see {@link #run}. */
    private OraResultBlock collected;
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
    private OraResultSet resultSet;
    private long updateCount = -1;
    private int maxRows;
    private int fetchSize;
    private boolean closed;
    /** {@code setQueryTimeout}, in seconds; 0 is no limit. */
    private int queryTimeout;
    private List<String> batch;

    OraStatement(OraConnection connection) {
        this.connection = connection;
        this.owner = connection.frontOrSelf();
        this.createdAt = connection.creationTrace();
    }

    // ---- executing -------------------------------------------------------

    @Override
    public boolean execute(String text) throws SQLException {
        String sql = escaped(text);
        return run(sql, null);
    }

    /**
     * Runs a statement, with bind variables or without.
     *
     * <p>The rows are collected while the answer is read; what the server says
     * about a statement that changed rows comes back as the update count.
     */
    boolean run(String sql, space.seclume.oracle.net.TtcBinds binds)
            throws SQLException {
        boolean[] hasRows = new boolean[1];
        underDeadline(sql, () -> hasRows[0] = runNow(sql, binds));
        return hasRows[0];
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

    private boolean runNow(String sql, space.seclume.oracle.net.TtcBinds binds)
            throws SQLException {
        // Every statement this driver runs passes here, with binds and
        // without. See space.seclume.jfr.
        space.seclume.jfr.Observed.Statement event =
                space.seclume.jfr.Observed.beginQuery("oracle");
        connection.sessionState().note(sql);
        boolean failed = true;
        try {
            boolean hasResult = runInto(sql, binds);
            failed = false;
            return hasResult;
        } finally {
            space.seclume.jfr.Observed.endQuery(event, "oracle", sql,
                    space.seclume.QueryFingerprint.Dialect.ORACLE,
                    block != null ? collectedRows : Math.max(0, updateCount), failed);
        }
    }

    private boolean runInto(String sql, space.seclume.oracle.net.TtcBinds binds)
            throws SQLException {
        checkOpen();
        OracleSession session = connection.session();
        resultLimit = session.resultLimit();
        collectingSql = sql;
        closeResult();
        // The statement is the handler itself. A lambda here would capture a
        // one-element array for the block and another for the counter - three
        // objects per query, before the first row arrives.
        collected = null;
        collectedRows = 0;
        // The cursor of the previous run goes back to the server, but only
        // for the same text: it stands for that statement and nothing else.
        // Without this the server opens a new cursor per execution and a loop
        // of a few hundred ends in ORA-01000.
        int reuse = session.cursorFor(sql);
        // A fetch size means: bring one block, the rest stays in the cursor.
        streaming = blockSize() > 0;
        TtcResult result = session.query(sql, binds, this, reuse, 1, null,
                session.columnsFor(sql), streaming);
        if (result.isFailure() && reuse != 0 && result.errorNumber() == STALE_DEFINE) {
            // The cursor was kept for this text, and the table under it has
            // changed since - dropped and re-created with another type in a
            // column. The server parses again on its own, but the cursor
            // still carries the types the first run was read in, and it
            // refuses to hand a LONG RAW over as the VARCHAR2 that stood there
            // before. A query that failed changed nothing, and Oracle rolls
            // back only the statement, never the transaction: so the cursor
            // goes and the text is parsed afresh, once. Found by the type
            // catalog, which re-creates one table per type.
            session.forgetCursor(sql, result.cursorId());
            collected = null;
            collectedRows = 0;
            result = session.query(sql, binds, this, 0, 1, null, java.util.List.of(),
                    streaming);
        }
        if (!result.isFailure() && result.cursorId() != 0
                && OracleSession.needsDefine(result.columns())) {
            // JSON or VECTOR in the result, and the cursor has no define yet:
            // what came back are locators that the next fetch spoils
            // (ORA-24826 from the second block on) and that cost a round trip
            // each to read. The cursor gets a define that brings the values
            // in the row, and runs again - two round trips once per cursor,
            // and from then on none per value. The rows of the first run go:
            // a query run twice has done nothing twice.
            java.util.List<space.seclume.oracle.net.OracleColumn> inline =
                    session.define(result.cursorId(), result.columns());
            collected = null;
            collectedRows = 0;
            result = session.query(sql, binds, this, result.cursorId(), 1, null, inline,
                    streaming);
        }
        if (result.isFailure()) {
            // Not kept: a statement that failed may have failed at parse,
            // and a cursor without a parsed statement answers every later
            // execution with ORA-01003 - forever, for that text on this
            // connection. See OracleSession.forgetCursor.
            session.forgetCursor(sql, result.cursorId());
        } else {
            session.rememberCursor(sql, result.cursorId(), result.columns());
        }
        lastReturned = result.returned();
        lastAnswer = result;
        OraResultBlock[] target = {collected};
        collected = null;
        if (result.isFailure()) {
            throw failure(result);
        }
        if (target[0] == null && !result.columns().isEmpty()) {
            target[0] = blockFor(result.columns());
        }
        block = target[0];
        resultSet = block == null ? null : new OraResultSet(block, this);
        // What the server reports as touched rows, and only for a statement
        // that returns none - JDBC wants -1 where there is a result set.
        updateCount = block == null ? result.affectedRows() : -1;
        return resultSet != null;
    }

    @Override
    public ResultSet executeQuery(String text) throws SQLException {
        String sql = escaped(text);
        execute(sql);
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

    /**
     * Runs one statement over many sets of values - Oracle's own batch.
     *
     * @return how many rows the server reports as changed, over all sets
     */
    long runArray(String sql, space.seclume.oracle.net.TtcBinds binds,
                  int iterations, space.seclume.oracle.net.TtcQuery.Rows rows)
            throws SQLException {
        checkOpen();
        OracleSession session = connection.session();
        closeResult();
        collected = null;
        collectedRows = 0;
        int reuse = session.cursorFor(sql);
        TtcResult result = session.query(sql, binds, this, reuse, iterations, rows,
                session.columnsFor(sql));
        if (result.isFailure()) {
            // Not kept: a statement that failed may have failed at parse,
            // and a cursor without a parsed statement answers every later
            // execution with ORA-01003 - forever, for that text on this
            // connection. See OracleSession.forgetCursor.
            session.forgetCursor(sql, result.cursorId());
        } else {
            session.rememberCursor(sql, result.cursorId(), result.columns());
        }
        if (result.isFailure()) {
            throw failure(result);
        }
        collected = null;
        updateCount = result.affectedRows();
        return updateCount;
    }

    /**
     * Takes one row over - called from inside the protocol read, once per row.
     *
     * <p>The row is a window onto the receive buffer and is gone as soon as
     * the next one is read, so it has to be copied here and not later.
     */
    @Override
    public void row(space.seclume.oracle.net.TtcRow row) throws SQLException {
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

    /**
     * Reads a cursor the server opened for an output bind.
     *
     * <p>A {@code SYS_REFCURSOR} comes back as a number and a description,
     * not as rows: the procedure opened a cursor and the client fetches from
     * it exactly as it would from a query of its own. That is the whole
     * difference from SQL Server, where a procedure simply selects and the
     * rows arrive with the answer.
     *
     * <p>The rows are read to the end here rather than block by block. A
     * cursor left half-read would have to survive the call that produced it,
     * and the statement it belongs to may be closed long before the
     * application walks the result - reading it out is the honest price for
     * handing back something that still works afterwards.
     *
     * <p>The block is this statement's own and is freed with it, so several
     * cursors out of one call do not overwrite each other.
     */
    ResultSet readCursor(int cursorId, java.util.List<space.seclume.oracle.net.OracleColumn> columns)
            throws SQLException {
        OraResultBlock into = new OraResultBlock(columns);
        cursorBlocks.add(into);
        space.seclume.oracle.OracleSession session = connection.session();
        TtcResult answer;
        do {
            answer = session.fetchMore(cursorId, FETCH_ROWS, row -> into.append(row), columns);
            if (answer.isFailure()) {
                throw failure(answer);
            }
        } while (!answer.isExhausted() && answer.rowCount() > 0);
        return new OraResultSet(into, this);
    }

    /** How many rows one fetch from a cursor asks for. */
    private static final int FETCH_ROWS = 100;

    /** Blocks allocated for cursors of an output bind - freed with the statement. */
    private final java.util.List<OraResultBlock> cursorBlocks = new java.util.ArrayList<>(1);

    /** Gives those blocks back; called from {@link #close}. */
    void closeCursorBlocks() {
        for (OraResultBlock block : cursorBlocks) {
            block.close();
        }
        cursorBlocks.clear();
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

    @Override
    public boolean getMoreResults() throws SQLException {
        checkOpen();
        closeResult();
        updateCount = -1;
        return false;
    }

    @Override
    public boolean getMoreResults(int current) throws SQLException {
        return getMoreResults();
    }

    /** The keys of the last statement, or {@code null}. */
    private ResultSet generatedKeys;
    /** What the last answer brought back in its output binds. */
    private java.util.List<byte[]> lastReturned = java.util.List.of();

    java.util.List<byte[]> lastReturned() {
        return lastReturned;
    }

    /**
     * The whole answer of the last execution.
     *
     * <p>A call with a cursor bind needs more of it than the output bytes:
     * the cursor the server opened and the columns it described.
     */
    private space.seclume.oracle.net.TtcResult lastAnswer;

    space.seclume.oracle.net.TtcResult lastAnswer() {
        return lastAnswer;
    }

    /** Takes what an {@code into} bind brought back as this statement's keys. */
    void keepAsGeneratedKeys(java.util.List<String> names, java.util.List<byte[]> values) {
        this.generatedKeys = new OraGeneratedKeys(this, names, values);
    }

    /**
     * Rewrites an {@code insert} so that Oracle hands the keys back.
     *
     * <p>Oracle has no separate channel for generated keys: the statement has
     * to say {@code returning <columns> into :n}, and the values arrive in
     * those bind variables. So the driver adds the clause and one output bind
     * per column - and reads what comes back in front of the answer.
     */
    static String withReturningInto(String sql, String[] columns, int firstBind) {
        StringBuilder text = new StringBuilder(sql.strip()); // seclume-allow: statement text, never a secret
        while (text.length() > 0 && text.charAt(text.length() - 1) == ';') {
            text.setLength(text.length() - 1);
        }
        text.append(" returning ");
        for (int i = 0; i < columns.length; i++) {
            text.append(i > 0 ? ", " : "").append(columns[i]);
        }
        text.append(" into ");
        for (int i = 0; i < columns.length; i++) {
            text.append(i > 0 ? ", " : "").append(':').append(firstBind + i);
        }
        return text.toString();
    }

    /**
     * Whether this result is being read in blocks - see {@code setFetchSize}.
     *
     * <p>Oracle needs no transaction for it: a cursor belongs to the session.
     * And unlike PostgreSQL it works for a plain statement too, because text
     * and values travel in the same call either way.
     */
    private boolean streaming;

    /**
     * Brings the next block of rows into the block the result set reads from.
     *
     * <p>The rows are copied into the block as they arrive, so here the block
     * is simply emptied and filled again - the memory of one block, not of the
     * whole result.
     */
    boolean fetchNextBlock() throws SQLException {
        if (!streaming || block == null) {
            return false;
        }
        OracleSession session = connection.session();
        if (!session.hasMoreRows()) {
            return false;
        }
        collected = block;
        collectedRows = 0;
        block.reset(block.columns());
        try {
            TtcResult more = session.fetchMore(session.openCursor(), fetchSize, this,
                    block.columns());
            if (more.isFailure()) {
                throw failure(more);
            }
        } finally {
            collected = null;
        }
        return block.rowCount() > 0;
    }

    /**
     * The block of this statement, ready for a new result - one per statement,
     * reused. A new one would mean a native allocation and a free per query.
     */
    private OraResultBlock blockFor(java.util.List<space.seclume.oracle.net.OracleColumn> columns) {
        if (reusable == null) {
            // A block another statement of this connection left behind, if
            // there is one: allocating and freeing one per statement is the
            // most expensive thing a shared arena can be asked to do.
            reusable = connection.takeSpareBlock();
        }
        if (reusable == null) {
            reusable = new OraResultBlock(columns);
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
        if (resultSet != null) {
            resultSet.discard();
            resultSet = null;
        }
        block = null;
    }

    /**
     * Oracle hands out generated keys through {@code returning ... into}, which
     * needs bind variables - so this cannot work before those do.
     */
    @Override
    public ResultSet getGeneratedKeys() throws SQLException {
        checkOpen();
        if (generatedKeys != null) {
            return generatedKeys;
        }
        return new OraGeneratedKeys(this, java.util.List.of(), java.util.List.of());
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

    /** One statement per round trip - Oracle has no batch of texts. */
    @Override
    public long[] executeLargeBatch() throws SQLException {
        checkOpen();
        if (batch == null || batch.isEmpty()) {
            return new long[0];
        }
        long[] counts = new long[batch.size()];
        for (int i = 0; i < counts.length; i++) {
            counts[i] = executeLargeUpdate(batch.get(i));
        }
        batch = null;
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
     * one go. Cursors in chunks are an open point - a silent failure would
     * be worse here than an honest "not yet".
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
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.ORACLE) : sql;
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
        if (autoGeneratedKeys != Statement.NO_GENERATED_KEYS) {
            throw keysNeedBinds();
        }
        return execute(sql);
    }

    @Override
    public boolean execute(String sql, int[] columnIndexes) throws SQLException {
        throw keysNeedBinds();
    }

    @Override
    public boolean execute(String sql, String[] columnNames) throws SQLException {
        throw keysNeedBinds();
    }

    @Override
    public int executeUpdate(String sql, int autoGeneratedKeys) throws SQLException {
        if (autoGeneratedKeys != Statement.NO_GENERATED_KEYS) {
            throw keysNeedBinds();
        }
        return executeUpdate(sql);
    }

    @Override
    public int executeUpdate(String sql, int[] columnIndexes) throws SQLException {
        throw keysNeedBinds();
    }

    @Override
    public int executeUpdate(String sql, String[] columnNames) throws SQLException {
        throw keysNeedBinds();
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

    /**
     * Keys asked of a plain statement.
     *
     * <p>Oracle hands them back through "returning into", which needs a bind
     * variable to return into - so only a prepared statement can. These
     * methods used to run the statement and quietly return no keys, which a
     * caller reads as "the insert produced none" rather than as "ask
     * differently".
     */
    private static SQLException keysNeedBinds() {
        return new java.sql.SQLFeatureNotSupportedException("generated keys on Oracle need "
                + "a prepared statement - use prepareStatement(sql, new String[] {\"ID\"})");
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
            closeCursorBlocks();
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
     * The server's error, number and wording.
     *
     * <p>The text comes straight from the server, so an {@code ORA-00942} says
     * which table is missing and a raised PL/SQL error says what it raised.
     * Without it a caller is left with a number to look up.
     */
    static SQLException failure(TtcResult result) {
        String number = "ORA-" + String.format("%05d", result.errorNumber());
        String text = result.errorText();
        String message = text == null || text.isBlank()
                ? "the server rejected the statement (" + number + ")"
                : "the server rejected the statement: " + text;
        return error(message, result.errorNumber());
    }

    /**
     * Oracle's error as the exception ojdbc raises for it: the same SQLState
     * and the same {@code SQLException} subclass.
     *
     * <p>Oracle sends no SQLState, so a driver has to invent one, and ojdbc's
     * are what every Oracle application has been written against - a
     * framework's translator, a {@code catch (SQLIntegrityConstraintViolationException
     * e)}, a check for 23000. The table was measured against ojdbc 23 by
     * raising each number from PL/SQL and reading what came back
     * ({@code ErrorCatalogTest} compares the everyday ones on every run); it
     * is a table of observed answers, not of anybody's code.
     *
     * <p>Two deliberate additions. A deadlock (ORA-00060) and a serialization
     * failure (ORA-08177) keep ojdbc's states but arrive as
     * {@link java.sql.SQLTransactionRollbackException}, and a discarded
     * package state (ORA-04061, ORA-04068) as a
     * {@link java.sql.SQLTransientException}: the server has undone the work
     * and running it again is the remedy, and that is exactly what those
     * types say - ojdbc throws the plain base class, so a retry written
     * against the types would never fire. Catching {@code SQLException}
     * catches them as before.
     */
    static SQLException error(String message, int number) {
        String state = sqlState(number);
        return switch (number) {
            case 60, 8177 -> new java.sql.SQLTransactionRollbackException(message, state, number);
            case 4061, 4068 -> new java.sql.SQLTransientException(message, state, number);
            case 911 -> new java.sql.SQLSyntaxErrorException(message, state, number);
            case 1013 -> new java.sql.SQLTimeoutException(message, state, number);
            case 18, 20, 3113, 12514 -> new java.sql.SQLRecoverableException(message, state,
                    number);
            default -> state.startsWith("08") || state.startsWith("28")
                    ? new SQLException(message, state, number)
                    : space.seclume.internal.jdbc.SqlErrors.of(message, state, number);
        };
    }

    /** The SQLState ojdbc gives an Oracle error number. */
    static String sqlState(int number) {
        return switch (number) {
            case 1, 1400, 2290, 2291, 2292 -> "23000";              // constraint violated
            case 900, 903, 904, 913, 917, 918, 923, 927, 933, 936, 942, 955, 957, 1031,
                 1722, 1741, 1756, 2049, 4091 -> "42000";           // syntax, access, invalid number
            case 911 -> "22019";                                    // invalid character
            case 1401 -> "22001";                                   // inserted value too large
            // ORA-12899, "value too large for column", is 72000 through ojdbc -
            // the generic bucket - and so it is here: code checks the number.
            case 1438 -> "22003";                                   // precision exceeded
            case 1476 -> "22012";                                   // division by zero
            case 1841, 1843, 1847, 1858, 1861 -> "22008";           // date out of range
            case 2091 -> "40000";                                   // transaction rolled back
            case 18, 20, 51, 54, 60, 4031 -> "61000";               // resources, deadlock
            case 100 -> "02000";                                    // no data found
            case 1002, 1410, 6511 -> "24000";                       // cursor state
            case 1422, 1427 -> "21000";                             // too many rows
            case 6502, 6508, 6512, 6530, 6531, 6550 -> "65000";     // PL/SQL
            case 12154 -> "66000";                                  // net service name
            case 3113, 12514 -> "08006";                            // connection lost
            case 28000, 28001, 30006, 38000 -> "99999";
            default -> "72000";                                     // everything else
        };
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
                space.seclume.QueryFingerprint.Dialect.ORACLE);
    }

}
