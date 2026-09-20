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
    private TdsResultBlock block;
    private TdsResultBlock reusable;
    /** Only set while a statement is being read - see {@link #collect}. */
    private TdsResultBlock collected;
    private int collectedRows;
    /** The statement being read, for the message of a result-limit failure. */
    private String collectingSql;
    /** What the connection was configured with; ResultLimit.NONE unless set. */
    private ResultLimit resultLimit = ResultLimit.NONE;
    private TdsResultSet resultSet;
    private long updateCount = -1;
    private int maxRows;
    private int fetchSize;
    private boolean closed;
    private List<String> batch;

    TdsStatement(TdsConnection connection) {
        this.connection = connection;
    }

    // ---- executing -------------------------------------------------------

    @Override
    public boolean execute(String sql) throws SQLException {
        checkOpen();
        TdsSession session = connection.session();
        collectingSql = sql;
        collect(session, handler -> session.sqlBatch(sql, handler));
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
        resultLimit = session.resultLimit();
        closeResult();
        // The statement is the handler itself. A lambda here would capture
        // the session, a one-element array for the block and another for the
        // counter - four objects per query, before the first row arrives.
        collected = null;
        collectedRows = 0;
        TokenStream stream = execution.run(this);
        if (collected == null && !stream.columns().isEmpty()) {
            // A select that found nothing: there is a result, it is empty.
            collected = blockFor(stream.columns());
        }
        TdsResultBlock[] target = {collected};
        collected = null;
        block = target[0];
        if (capturingGeneratedKeys) {
            // The statement was sent as "<insert>;select scope_identity()", so
            // the rows that came back are the key and not a result the caller
            // asked for. The count has to come from the first statement of the
            // two: the select reports one row of its own, which for a one-row
            // insert is the same number by coincidence and not otherwise.
            closeGeneratedKeys();
            generatedKeys = block;
            block = null;
            resultSet = null;
            updateCount = stream.firstUpdateCount();
            return;
        }
        resultSet = block == null ? null : new TdsResultSet(block, this);
        updateCount = block != null ? -1 : stream.updateCount();
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
        if (!streaming || block == null || cursor == 0 || lastBlock < fetchSize) {
            return false;
        }
        TdsSession session = connection.session();
        collected = block;
        collectedRows = 0;
        block.reset(block.columns());
        try {
            lastBlock = session.cursorFetch(cursor, fetchSize, this);
        } finally {
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
        if (resultSet != null) {
            resultSet.close();
            resultSet = null;
        }
        block = null;
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
        if (direction != ResultSet.FETCH_FORWARD) {
            throw new SQLFeatureNotSupportedException("seclume result sets move forward only");
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
                    "seclume does not send an ATTENTION packet yet - a timeout here "
                    + "would be a lie");
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
                "seclume does not send an ATTENTION packet yet");
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
}
