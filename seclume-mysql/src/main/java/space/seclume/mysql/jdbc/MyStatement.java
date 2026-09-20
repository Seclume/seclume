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
    private MyResultBlock block;
    private MyResultBlock reusable;
    /** Only set while a statement is being read - see {@link #collect}. */
    private MySession collecting;
    private boolean collectingBinary;
    private MyResultBlock collected;
    private int collectedRows;
    /** The statement being read, for the message of a result-limit failure. */
    private String collectingSql;
    /** What the connection was configured with; ResultLimit.NONE unless set. */
    private ResultLimit resultLimit = ResultLimit.NONE;
    private MyResultSet resultSet;
    private long updateCount = -1;
    private long generatedKey;
    private int maxRows;
    private int fetchSize;
    private boolean closed;
    private List<String> batch;

    MyStatement(MyConnection connection) {
        this.connection = connection;
    }

    // ---- executing -------------------------------------------------------

    @Override
    public boolean execute(String sql) throws SQLException {
        checkOpen();
        MySession session = connection.session();
        collectingSql = sql;
        collect(session, handler -> session.query(sql, handler), false);
        return resultSet != null;
    }

    @Override
    public ResultSet executeQuery(String sql) throws SQLException {
        execute(sql);
        if (resultSet == null) {
            throw new SQLException("the statement returned no rows: " + sql
                    + " - use executeUpdate for statements that do not select");
        }
        return resultSet;
    }

    @Override
    public int executeUpdate(String sql) throws SQLException {
        return (int) Math.min(executeLargeUpdate(sql), Integer.MAX_VALUE);
    }

    @Override
    public long executeLargeUpdate(String sql) throws SQLException {
        execute(sql);
        return Math.max(updateCount, 0);
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
        streaming = fetchSize > 0;
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
            reusable = new MyResultBlock(fields, binary);
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
            resultSet.close();
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
    public void addBatch(String sql) throws SQLException {
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
        if (direction != ResultSet.FETCH_FORWARD) {
            throw new SQLFeatureNotSupportedException(
                    "seclume result sets move forward only");
        }
    }

    @Override
    public int getResultSetType() {
        return ResultSet.TYPE_FORWARD_ONLY;
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
        return 0;
    }

    @Override
    public void setQueryTimeout(int seconds) throws SQLException {
        if (seconds != 0) {
            throw new SQLFeatureNotSupportedException(
                    "seclume cannot kill a running query yet - that needs a second "
                    + "connection and KILL QUERY, so a timeout here would be a lie");
        }
    }

    @Override
    public int getMaxFieldSize() {
        return 0;
    }

    @Override
    public void setMaxFieldSize(int max) throws SQLException {
        if (max != 0) {
            throw new SQLFeatureNotSupportedException("seclume does not truncate column values");
        }
    }

    @Override
    public void setEscapeProcessing(boolean enable) throws SQLException {
        if (enable) {
            throw new SQLFeatureNotSupportedException(
                    "seclume passes SQL to the server unchanged - JDBC escape syntax "
                    + "like {fn ...} is not rewritten");
        }
    }

    @Override
    public void cancel() throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "seclume does not implement KILL QUERY on a second connection yet");
    }

    @Override
    public void setCursorName(String name) throws SQLException {
        throw new SQLFeatureNotSupportedException("seclume has no updatable cursors");
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
        throw new SQLFeatureNotSupportedException(
                "seclume does not close statements automatically");
    }

    @Override
    public boolean isCloseOnCompletion() {
        return false;
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

    // ---- state -----------------------------------------------------------

    @Override
    public Connection getConnection() throws SQLException {
        checkOpen();
        return connection;
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
}
