package space.seclume.mysql.jdbc;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

import space.seclume.internal.jdbc.ResultLimit;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLWarning;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import space.seclume.mysql.MyParameters;
import space.seclume.mysql.MySession;

/**
 * A statement without parameters, in the text protocol ({@code COM_QUERY}).
 *
 * <p>While being read the rows move straight into a {@link MyResultBlock}, that
 * is into one native block instead of objects per cell. The receive buffer is
 * free again afterwards, and the {@code ResultSet} holds on to nothing that
 * belongs to the session - only that way may it survive the next query.
 */
class MyStatement implements Statement, MySession.RowHandler {

    final MyConnection connection;
    /** The connection this was made through, as the application sees it - see {@link space.seclume.internal.jdbc.Fronted}. */
    private final Connection owner;
    private MyResultBlock block;
    private MyResultBlock reusable;
    /** Only set while a statement is being read - see {@link #collect}. */
    private MySession collecting;
    private boolean collectingBinary;
    private MyResultBlock collected;
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
    private MyResultSet resultSet;
    private long updateCount = -1;
    private long generatedKey;
    private int maxRows;
    private int fetchSize;
    private boolean closed;
    /** {@code setQueryTimeout}, in seconds; 0 is no limit. */
    private int queryTimeout;
    private List<String> batch;

    MyStatement(MyConnection connection) {
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
        MySession session = connection.session();
        collectingSql = sql;
        collect(session, handler -> session.query(sql, handler), false);
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

    /** What the caller issues themselves - text or binary protocol. */
    @FunctionalInterface
    interface Execution {
        void run(MySession.RowHandler handler) throws SQLException;
    }

    /**
     * Executes and puts the rows straight into the native block along the way.
     *
     * <p>The rows are windows onto the receive buffer and have to be taken over
     * before the next packet is read. That is why copying happens during the
     * read, not after it.
     */
    void collect(MySession session, Execution execution, boolean binary) throws SQLException {
        // Every statement this driver runs passes here, text protocol and
        // binary, which is why the recording hangs off this method rather
        // than off the entry points above it. See space.seclume.jfr.
        space.seclume.jfr.Observed.Statement event =
                space.seclume.jfr.Observed.beginQuery("mysql");
        connection.sessionState().note(collectingSql);
        boolean failed = true;
        try {
            collectInto(session, execution, binary);
            failed = false;
        } finally {
            space.seclume.jfr.Observed.endQuery(event, "mysql", collectingSql,
                    space.seclume.QueryFingerprint.Dialect.MYSQL,
                    block != null ? rowsCollected : Math.max(0, updateCount), failed);
        }
    }

    /** How many rows the last collect took over - for the recording. */
    private long rowsCollected;

    private void collectInto(MySession session, Execution execution, boolean binary)
            throws SQLException {
        resultLimit = session.resultLimit();
        closeResult();
        // The statement is the handler itself. A lambda here would capture
        // the session, a one-element array for the block and another for the
        // counter - four objects per query, before the first row arrives.
        collecting = session;
        collectingBinary = binary;
        collected = null;
        collectedRows = 0;
        execution.run(this);
        List<MySession.Field> fields = session.fields();
        if (collected == null && !fields.isEmpty()) {
            collected = blockFor(fields, binary);
        }
        MyResultBlock[] target = {collected};
        rowsCollected = collectedRows;
        collecting = null;
        collected = null;
        block = target[0];
        resultSet = block == null ? null : new MyResultSet(block, this);
        updateCount = block != null ? -1 : session.affectedRows();
        generatedKey = session.lastInsertId();
    }

    /**
     * Takes one row over - called from inside the protocol read, once per row.
     *
     * <p>The row is a window onto the receive buffer and is gone as soon as
     * the next packet is read, so it has to be copied here and not later.
     */
    @Override
    public void row(space.seclume.mysql.MyRow row) throws SQLException {
        if (collected == null) {
            collected = blockFor(collecting.fields(), collectingBinary);
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

    /** Runs a prepared plan; the rows arrive in binary. */
    void executePrepared(MySession session, MySession.Prepared statement, MyParameters parameters)
            throws SQLException {
        // A fetch size means: the server keeps the rows and hands them out in
        // blocks. The execute then brings the descriptions and nothing else,
        // so the first block is fetched right here.
        //
        // Only for a statement that has columns. The prepare said how many,
        // and an insert, update or delete has none: executed with a cursor it
        // still ran - the row was written - and the fetch behind it failed
        // with "no open cursor", so a write reported an error after it had
        // happened. A fetch size set on every statement, as frameworks set
        // it, did that to every write.
        streaming = blockSize() > 0 && !statement.fields().isEmpty();
        cursor = streaming ? statement : null;
        if (streaming) {
            session.executePreparedWithCursor(statement, parameters);
            collect(session, handler -> session.fetchFromCursor(statement, fetchSize, handler),
                    true);
            return;
        }
        collect(session, handler -> session.executePrepared(statement, parameters, handler), true);
    }

    /** Whether this result is being read in blocks - see {@code setFetchSize}. */
    private boolean streaming;
    /** The statement whose cursor is open, or {@code null}. */
    private MySession.Prepared cursor;

    /**
     * Brings the next block of rows into the block the result set reads from.
     *
     * <p>The rows are copied into the block as they arrive, so the block is
     * emptied and filled again - the memory of one block, not of the result.
     */
    boolean fetchNextBlock() throws SQLException {
        if (!streaming || block == null || cursor == null) {
            return false;
        }
        MySession session = connection.session();
        if (!session.isCursorOpen()) {
            return false;
        }
        collecting = session;
        collected = block;
        collectedRows = 0;
        block.reset(session.fields(), true);
        try {
            session.fetchFromCursor(cursor, fetchSize, this);
        } finally {
            collected = null;
            collecting = null;
        }
        return block.rowCount() > 0;
    }

    /** Lets go of a cursor the caller stopped reading from. */
    void closeCursorIfOpen() throws SQLException {
        if (streaming && cursor != null) {
            connection.session().closeCursor(cursor);
            cursor = null;
            streaming = false;
        }
    }

    ResultSet currentResultSet() {
        return resultSet;
    }

    long updateCountValue() {
        return updateCount;
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

    /**
     * The block of this statement, ready for a new result - one per statement,
     * reused. A new one would mean a native allocation and a free per query.
     */
    private MyResultBlock blockFor(List<MySession.Field> fields, boolean binary) {
        if (reusable == null) {
            // A block another statement of this connection left behind, if
            // there is one: allocating and freeing one per statement is the
            // most expensive thing a shared arena can be asked to do.
            reusable = connection.takeSpareBlock();
        }
        if (reusable == null) {
            reusable = new MyResultBlock(fields, binary, connection.tinyInt1isBit());
        } else {
            reusable.reset(fields, binary);
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
     * The key {@code AUTO_INCREMENT} just handed out.
     *
     * <p>Unlike with PostgreSQL this works here: MySQL sends it along in the OK
     * packet, without an extra query. A result with one column
     * {@code GENERATED_KEY} is exactly what JDBC provides for this.
     */
    @Override
    public ResultSet getGeneratedKeys() throws SQLException {
        checkOpen();
        MySession session = connection.session();
        long key = generatedKey;
        MyStatement helper = new MyStatement(connection);
        helper.collect(session,
                handler -> session.query("select " + key + " as GENERATED_KEY", handler), false);
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
     * Accepted and remembered, but without effect: this state fetches every
     * result in one go. Cursors in chunks are
     * an open point, named in the README - a silent failure would
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
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.MYSQL) : sql;
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
                space.seclume.QueryFingerprint.Dialect.MYSQL);
    }

}
