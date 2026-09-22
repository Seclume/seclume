package space.seclume.postgresql.jdbc;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

import space.seclume.internal.jdbc.ResultLimit;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLWarning;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import space.seclume.postgresql.PgSession;

/**
 * A statement without parameters, in the simple protocol.
 *
 * <p>While being read the rows move straight into a {@link ResultBlock}, that
 * is into one native block instead of objects per cell. The session's receive
 * buffer is free again afterwards, and the {@code ResultSet} holds on to
 * nothing that belongs to the session - only that way may it survive the next
 * query.
 */
class PgStatement implements Statement, PgSession.RowHandler {

    final PgConnection connection;
    private ResultBlock block;
    private ResultBlock reusable;
    /** Only set while a statement is being read - see {@link #collect}. */
    private PgSession collecting;
    private ResultBlock collected;
    private int collectedRows;
    /** The statement being read, for the message of a result-limit failure. */
    private String collectingSql;
    private PgResultSet resultSet;
    private long updateCount = -1;
    private int maxRows;
    private int fetchSize;
    private boolean closed;
    private List<String> batch;

    PgStatement(PgConnection connection) {
        this.connection = connection;
    }

    // ---- executing -------------------------------------------------------

    @Override
    public boolean execute(String sql) throws SQLException {
        run(sql);
        return resultSet != null;
    }

    @Override
    public ResultSet executeQuery(String sql) throws SQLException {
        run(sql);
        if (resultSet == null) {
            throw new SQLException("the statement returned no rows: " + sql
                    + " - use executeUpdate for statements that do not select");
        }
        return resultSet;
    }

    @Override
    public int executeUpdate(String sql) throws SQLException {
        run(sql);
        return (int) Math.min(Math.max(updateCount, 0), Integer.MAX_VALUE);
    }

    @Override
    public long executeLargeUpdate(String sql) throws SQLException {
        run(sql);
        return Math.max(updateCount, 0);
    }

    private void run(String sql) throws SQLException {
        checkOpen();
        PgSession session = connection.session();
        collectingSql = sql;
        if (wantsBlocks()) {
            runInBlocks(session, sql);
            return;
        }
        decideStreaming(false);
        collect(session, handler -> session.simpleQuery(sql, handler));
    }

    /**
     * Whether this plain statement should go the long way round.
     *
     * <p>Only when the caller asked for a fetch size and there is a
     * transaction to hold the portal. With the default of zero nothing here
     * changes, which is the point: the simple protocol stays the fast path
     * for the overwhelming majority of statements.
     */
    private boolean wantsBlocks() throws SQLException {
        return fetchSize > 0 && !connection.getAutoCommit();
    }

    /**
     * A plain statement, executed through the extended protocol so that a
     * fetch size can mean something.
     *
     * <p>The simple protocol has no row limit: the server sends every row of
     * the result and the driver has to take them all. So a
     * {@code createStatement()} with a fetch size used to read a whole table
     * into memory, where pgjdbc, Connector/J and ojdbc all hand back bounded
     * memory - measured, not assumed, in {@code FetchSizeProbe}. An
     * application that reads a large table the ordinary way would have had to
     * find that out for itself, which is not a thing a drop-in replacement
     * may ask of anybody.
     *
     * <p>The unnamed statement and portal are used, so nothing is left on the
     * server: this is a one-shot execution, not a plan worth keeping. The
     * blocks themselves are fetched by {@code fetchNextBlock}, the same code
     * a prepared statement uses.
     */
    private void runInBlocks(PgSession session, String sql) throws SQLException {
        session.parseLater(UNNAMED, sql);
        decideStreaming(true);
        beginExecution(session, NO_PARAMETERS, UNNAMED, executeLimit(), sql);
    }

    /** PostgreSQL's unnamed prepared statement and portal - not kept by the server. */
    private static final String UNNAMED = "";

    /** A plain statement has none, and the object is immutable in practice. */
    private static final space.seclume.postgresql.PgParameters NO_PARAMETERS =
            new space.seclume.postgresql.PgParameters(0);

    /** What the caller issues themselves - simple or extended protocol. */
    @FunctionalInterface
    interface Execution {
        void run(PgSession.RowHandler handler) throws SQLException;
    }

    /**
     * Whether this result is being read in blocks - see {@link #setFetchSize}.
     *
     * <p>One condition from the protocol: only <b>inside a transaction</b>,
     * because outside it the {@code Sync} ends the implicit transaction and
     * takes the portal with it. A fetch size outside a transaction therefore
     * cannot be honoured by anyone, and is ignored here as it is everywhere
     * else.
     *
     * <p>It used to need a <b>prepared</b> statement as well, on the grounds
     * that only the extended protocol has a row limit. That is true of the
     * protocol and was the wrong conclusion for the driver: the answer is to
     * take a plain statement through the extended protocol rather than to
     * ignore what the caller asked for. See {@code runInBlocks}.
     */
    private boolean streaming;

    /** The row limit for the next execution: a block, or the whole result. */
    int executeLimit() throws SQLException {
        int max = getMaxRows();
        if (!streaming) {
            return max;
        }
        return max > 0 ? Math.min(max, fetchSize) : fetchSize;
    }

    /** Decides once per execution whether the rows come in blocks. */
    void decideStreaming(boolean prepared) throws SQLException {
        streaming = prepared && fetchSize > 0 && !connection.getAutoCommit();
    }

    /**
     * Brings the next block of rows into the block the result set reads from.
     *
     * <p>The buffer is swapped, not copied: what the session read into becomes
     * the memory of the result again, and the memory the result had - whose
     * rows are read and done with - goes back to the session. A million rows
     * therefore cost the memory of one block, not of a million rows.
     */
    boolean fetchNextBlock() throws SQLException {
        if (!streaming || block == null) {
            return false;
        }
        PgSession session = connection.session();
        if (!session.isPortalSuspended()) {
            return false;
        }
        collecting = session;
        collected = block;
        collectedRows = 0;
        block.reset(block.fields());
        session.beginCollect();
        try {
            session.executeMore(executeLimit(), this);
        } finally {
            session.endCollect();
            collected.adopt(session::exchangeBuffer);
            collected = null;
            collecting = null;
        }
        return block.rowCount() > 0;
    }

    /** Lets go of a portal the caller stopped reading from. */
    void closePortalIfOpen() throws SQLException {
        if (streaming) {
            connection.session().closePortal();
            streaming = false;
        }
    }

    /**
     * Executes and puts the rows straight into the native block along the way.
     *
     * <p>Both protocols end up here. The rows are <b>not</b> copied out: while
     * the answer is being read the receive buffer stays still, the reader only
     * writes down where each value is, and at the end this result takes the
     * whole buffer over and gives the session its own in exchange. A thousand
     * rows of three columns cost three thousand pairs of numbers instead of
     * three thousand copies.
     */

    void collect(PgSession session, Execution execution) throws SQLException {
        // Every statement this driver runs passes here, both protocols, which
        // is why the recording hangs off this method and not off the several
        // entry points above it. See space.seclume.jfr.
        space.seclume.jfr.Observed.Statement event =
                space.seclume.jfr.Observed.beginQuery("postgresql");
        boolean failed = true;
        try {
            collectInto(session, execution);
            failed = false;
        } finally {
            space.seclume.jfr.Observed.endQuery(event, "postgresql", collectingSql,
                    space.seclume.QueryFingerprint.Dialect.POSTGRESQL,
                    block != null ? rowsCollected : Math.max(0, updateCount), failed);
        }
    }

    /** How many rows the last collect took over - for the recording. */
    private long rowsCollected;

    private void collectInto(PgSession session, Execution execution) throws SQLException {
        closeResult();
        // The statement is the handler itself. A lambda here would capture the
        // session, a one-element array for the block and another for the
        // counter - four objects per query, and a query that returns one row
        // should not allocate four objects before the row arrives.
        collecting = session;
        collected = null;
        collectedRows = 0;
        session.beginCollect();
        try {
            execution.run(this);
        } finally {
            session.endCollect();
            if (collected != null) {
                // The buffer that holds the rows becomes the memory of this
                // result; the session gets the empty one in exchange.
                collected.adopt(session::exchangeBuffer);
            }
        }
        List<PgSession.Field> fields = session.fields();
        if (collected == null && !fields.isEmpty()) {
            collected = blockFor(fields);
        }
        block = collected;
        rowsCollected = collectedRows;
        collecting = null;
        collected = null;
        resultSet = block == null ? null : new PgResultSet(block, this);
        updateCount = block != null ? -1 : affectedRows(session.lastCommandTag());
    }

    /**
     * Takes one row over - called from inside the protocol read, once per row.
     *
     * <p>The row is a window onto the receive buffer and is gone as soon as
     * the next message is read, so it has to be copied here and not later.
     */
    @Override
    public void row(space.seclume.postgresql.Row row) throws SQLException {
        if (collected == null) {
            collected = blockFor(collecting.fields());
        }
        if (maxRows == 0 || collectedRows < maxRows) {
            collected.append(row);
            collectedRows++;
            // One comparison against a field that is zero when nothing is
            // configured - and the difference between an error that names the
            // query and an OutOfMemoryError that names nothing.
            ResultLimit limit = collecting.resultLimit();
            if (limit.isSet()) {
                limit.check(collected.bytes(), collectedRows, collectingSql);
            }
        }
    }

    /** Runs a prepared plan; the rows land the same way as above. */
    void beginExecution(PgSession session, space.seclume.postgresql.PgParameters params,
                        String statementName, int limit, String sql) throws SQLException {
        beginExecution(session, params, statementName, limit, sql, null);
    }

    /**
     * The same, for a statement whose result shape is already known - then the
     * {@code DESCRIBE} is left out. See {@code PgSession.bindAndExecute}.
     */
    void beginExecution(PgSession session, space.seclume.postgresql.PgParameters params,
                        String statementName, int limit, String sql,
                        java.util.List<PgSession.Field> known) throws SQLException {
        collectingSql = sql;
        collect(session, handler ->
                session.bindAndExecute(statementName, params, limit, handler, known));
    }

    ResultSet currentResultSet() {
        return resultSet;
    }

    long updateCountValue() {
        return updateCount;
    }

    /**
     * The row count from the command tag - {@code "INSERT 0 2"},
     * {@code "UPDATE 7"}, {@code "SELECT 3"}. With {@code INSERT} the OID comes
     * before it, which has always been 0 since PostgreSQL 12.
     */
    static long affectedRows(String tag) {
        if (tag == null || tag.isEmpty()) {
            return 0;
        }
        int space = tag.lastIndexOf(' ');
        if (space < 0) {
            return 0;
        }
        try {
            return Long.parseLong(tag.substring(space + 1));
        } catch (NumberFormatException e) {
            return 0;
        }
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

    /** This driver returns exactly one result per execution. */
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
     * The block of this statement, ready for a new result.
     *
     * <p>One per statement, reused - a new one would mean a native allocation
     * and a free for every single query.
     */
    private ResultBlock blockFor(List<PgSession.Field> fields) {
        if (reusable == null) {
            // A block another statement of this connection left behind, if
            // there is one: allocating and freeing one per statement is the
            // most expensive thing a shared arena can be asked to do.
            reusable = connection.takeSpareBlock();
        }
        if (reusable == null) {
            reusable = new ResultBlock(fields);
        } else {
            reusable.reset(fields);
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
     * result in one go. Reading portals in chunks is recorded in
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
                    "seclume cannot cancel a running query yet - the CancelRequest "
                    + "message is not implemented, so a timeout here would be a lie");
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
                "seclume does not implement the CancelRequest message yet");
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
        throw new SQLFeatureNotSupportedException("seclume does not close statements automatically");
    }

    @Override
    public boolean isCloseOnCompletion() {
        return false;
    }

    // ---- generated keys --------------------------------------------------


    /**
     * Turns a statement into one that hands its rows back.
     *
     * <p>PostgreSQL has no separate channel for generated keys, and it does
     * not need one: {@code returning} makes the insert answer with the rows it
     * wrote, keys and all. So "generated keys" here is a rewrite, not a second
     * protocol - and that is also why it is honest: what comes back is what
     * the server really stored, not what the client hoped for.
     *
     * <p>A statement that already says {@code returning} is left alone; asking
     * for keys twice would be a syntax error.
     *
     * @param columns the columns wanted, or {@code null} for all of them
     */
    static String withReturning(String sql, String[] columns) {
        String trimmed = sql.strip();
        while (trimmed.endsWith(";")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1).strip();
        }
        if (saysReturning(trimmed)) {
            return trimmed;
        }
        if (columns == null || columns.length == 0) {
            return trimmed + " returning *";
        }
        StringBuilder text = new StringBuilder(trimmed); // seclume-allow: statement text, never a secret
        text.append(" returning ");
        for (int i = 0; i < columns.length; i++) {
            if (i > 0) {
                text.append(", ");
            }
            text.append(quoteName(columns[i]));
        }
        return text.toString();
    }

    /** Whether the last word outside a literal is already a returning clause. */
    private static boolean saysReturning(String sql) {
        String plain = sql.toLowerCase(java.util.Locale.ROOT);
        int at = plain.lastIndexOf("returning");
        if (at < 0) {
            return false;
        }
        // Only count it when it stands as a word of its own.
        boolean beforeIsSpace = at == 0 || Character.isWhitespace(plain.charAt(at - 1));
        int after = at + "returning".length();
        boolean afterIsSpace = after >= plain.length()
                || Character.isWhitespace(plain.charAt(after));
        return beforeIsSpace && afterIsSpace;
    }

    /** A column name as the server has to read it - quoted, quotes doubled. */
    private static String quoteName(String name) {
        return "\"" + name.replace("\"", "\"\"") + "\"";
    }

    /**
     * The rows the statement wrote back.
     *
     * <p>Empty when the statement was not asked for keys - JDBC wants an empty
     * result set there, not an exception.
     */
    @Override
    public ResultSet getGeneratedKeys() throws SQLException {
        checkOpen();
        if (generatedKeys != null) {
            return generatedKeys;
        }
        return new PgResultSet(blockFor(java.util.List.of()), this);
    }

    /** Set by the connection when the caller asked for generated keys. */
    void expectGeneratedKeys() {
        this.wantsGeneratedKeys = true;
    }

    boolean wantsGeneratedKeys() {
        return wantsGeneratedKeys;
    }

    /** Takes the result of a rewritten statement over as the keys. */
    void keepAsGeneratedKeys() {
        this.generatedKeys = resultSet;
        this.resultSet = null;
        this.updateCount = Math.max(this.updateCount, block == null ? 0 : block.rowCount());
    }

    private boolean wantsGeneratedKeys;
    private PgResultSet generatedKeys;

    @Override
    public boolean execute(String sql, int autoGeneratedKeys) throws SQLException {
        return executeWithKeys(sql, autoGeneratedKeys != Statement.NO_GENERATED_KEYS);
    }

    @Override
    public boolean execute(String sql, int[] columnIndexes) throws SQLException {
        return executeWithKeys(sql, true);
    }

    @Override
    public boolean execute(String sql, String[] columnNames) throws SQLException {
        wantsGeneratedKeys = true;
        boolean hasResult = execute(withReturning(sql, columnNames));
        keepAsGeneratedKeys();
        return hasResult && generatedKeys == null;
    }

    @Override
    public int executeUpdate(String sql, int autoGeneratedKeys) throws SQLException {
        executeWithKeys(sql, autoGeneratedKeys != Statement.NO_GENERATED_KEYS);
        return (int) Math.max(updateCount, 0);
    }

    @Override
    public int executeUpdate(String sql, int[] columnIndexes) throws SQLException {
        executeWithKeys(sql, true);
        return (int) Math.max(updateCount, 0);
    }

    @Override
    public int executeUpdate(String sql, String[] columnNames) throws SQLException {
        executeWithKeys(sql, true);
        return (int) Math.max(updateCount, 0);
    }

    private boolean executeWithKeys(String sql, boolean wantsKeys) throws SQLException {
        if (!wantsKeys) {
            return execute(sql);
        }
        wantsGeneratedKeys = true;
        boolean hasResult = execute(withReturning(sql, null));
        keepAsGeneratedKeys();
        return hasResult && generatedKeys == null;
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
                // Not freed: the connection keeps it for the next statement.
                // See PgConnection#takeSpareBlock for what that is worth.
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
