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

    final OraConnection connection;
    private OraResultBlock block;
    private OraResultBlock reusable;
    /** Only set while a statement is being read - see {@link #run}. */
    private OraResultBlock collected;
    private int collectedRows;
    /** The statement being read, for the message of a result-limit failure. */
    private String collectingSql;
    /** What the connection was configured with; ResultLimit.NONE unless set. */
    private ResultLimit resultLimit = ResultLimit.NONE;
    private OraResultSet resultSet;
    private long updateCount = -1;
    private int maxRows;
    private int fetchSize;
    private boolean closed;
    private List<String> batch;

    OraStatement(OraConnection connection) {
        this.connection = connection;
    }

    // ---- executing -------------------------------------------------------

    @Override
    public boolean execute(String sql) throws SQLException {
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
        streaming = fetchSize > 0;
        TtcResult result = session.query(sql, binds, this, reuse, 1, null,
                session.columnsFor(sql), streaming);
        session.rememberCursor(sql, result.cursorId(), result.columns());
        lastReturned = result.returned();
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
        session.rememberCursor(sql, result.cursorId(), result.columns());
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
            resultSet.close();
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
     * one go. Cursors in chunks are recorded in
     * {@code docs/protocol/oracle.md} as an open point - a silent failure
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
                    "seclume does not send an Oracle break marker yet - a timeout "
                    + "here would be a lie");
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
                "seclume does not send an Oracle break marker yet");
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
        return new SQLException(message, "42000", result.errorNumber());
    }
}
