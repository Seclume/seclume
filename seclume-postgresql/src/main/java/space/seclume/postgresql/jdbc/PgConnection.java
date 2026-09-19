package space.seclume.postgresql.jdbc;

import space.seclume.Pipelined;
import space.seclume.RoundTrips;
import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;

import space.seclume.internal.jdbc.CallSyntax;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.NClob;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLClientInfoException;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Struct;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicLong;

import space.seclume.postgresql.PgSession;

/**
 * A JDBC connection on top of a {@link PgSession}.
 *
 * <p>The connection holds no password. It needed one when it was opened, and
 * that one lived in native memory which was zeroed afterwards. Anyone closing
 * and reopening it goes through the {@code SecretProvider} again - there is
 * nothing that could be reused, and that is exactly the intention.
 */
public final class PgConnection implements Connection, RoundTrips, Pipelined {

    private final PgSession session;
    private final String url;
    private final List<PgStatement> open = new ArrayList<>();
    private final AtomicLong statementCounter = new AtomicLong();
    private boolean autoCommit = true;
    private boolean readOnly;
    private boolean closed;
    private int isolation = TRANSACTION_READ_COMMITTED;

    PgConnection(PgSession session, String url) {
        this(session, url, SeclumeUrl.DEFAULT_STATEMENT_CACHE);
    }

    PgConnection(PgSession session, String url, int statementCacheSize) {
        this.session = session;
        this.url = url;
        this.statementCacheSize = Math.max(statementCacheSize, 0);
    }

    // ---- the plan cache --------------------------------------------------

    /**
     * Plans this connection has parsed and nobody is using at the moment.
     *
     * <p>Without it every {@code prepareStatement} is a fresh plan on the
     * server, parsed and planned and thrown away again - measured at eleven
     * microseconds over a loopback connection against pgjdbc, which keeps such
     * a cache and is otherwise level with us. Whoever uses the seclume pool
     * never notices, because the pool caches the JDBC statements themselves;
     * whoever uses the driver on its own pays it on every call.
     *
     * <p>A plan goes in when its statement is <b>closed</b>, not when it is
     * created. That is what makes the whole thing safe: two live statements
     * can never share a plan name, and with it the unnamed portal, so nothing
     * can interleave. And only a plan that has run at least once successfully
     * is kept - a statement whose Parse failed has no plan on the server, and
     * caching that name would hand the next caller a Bind against nothing.
     */
    private final java.util.LinkedHashMap<String, Idle> idlePlans =
            new java.util.LinkedHashMap<>(16, 0.75f, true);
    private final int statementCacheSize;

    /** A parsed plan, with what the server said its columns are. */
    private record Idle(String name, List<PgSession.Field> described) {
    }

    /** Takes an idle plan for this SQL, or null when there is none. */
    private Idle takePlan(String sql) {
        return statementCacheSize == 0 ? null : idlePlans.remove(sql);
    }

    /**
     * Gives a plan back, or releases it when the cache is full or off.
     *
     * @param described what the statement returns, or null when it never ran -
     *                  in that case the plan is released rather than kept
     */
    void releasePlan(String sql, String name, List<PgSession.Field> described)
            throws SQLException {
        if (statementCacheSize == 0 || described == null) {
            session.closeStatementLater(name);
            return;
        }
        Idle previous = idlePlans.put(sql, new Idle(name, described));
        if (previous != null) {
            // Two statements on the same SQL were open at once; only one plan
            // is worth keeping.
            session.closeStatementLater(previous.name());
        }
        while (idlePlans.size() > statementCacheSize) {
            var oldest = idlePlans.entrySet().iterator();
            Idle evicted = oldest.next().getValue();
            oldest.remove();
            session.closeStatementLater(evicted.name());
        }
    }

    /** A result block a closed statement left behind - see takeSpareBlock. */
    private ResultBlock spare;

    PgSession session() throws SQLException {
        checkOpen();
        return session;
    }

    String url() {
        return url;
    }

    void forget(PgStatement statement) {
        open.remove(statement);
    }

    /**
     * One spare result block per connection, kept instead of freed.
     *
     * <p>Measured, and it was the single most expensive thing in the whole
     * driver under load: the block's memory lives in a <b>shared</b> arena -
     * it has to, because a pooled connection is opened on one thread and
     * closed on another - and closing a shared arena makes the JVM coordinate
     * with every other thread. Half of all runnable time went into
     * {@code closeScope0} while eight threads did nothing but borrow, query
     * and return, because every {@code createStatement}/{@code close} pair
     * freed a block.
     *
     * <p>So a closed statement leaves its block here and the next one picks it
     * up. At most one is kept, so the memory of a connection stays bounded,
     * and it is freed for good when the connection closes - deterministically,
     * as everything in this library is.
     */
    ResultBlock takeSpareBlock() {
        ResultBlock block = spare;
        spare = null;
        return block;
    }

    /** Takes a block back from a statement that is closing. */
    void recycleBlock(ResultBlock block) {
        if (spare == null) {
            spare = block;
        } else {
            block.close();
        }
    }

    // ---- statements ------------------------------------------------------

    @Override
    public Statement createStatement() throws SQLException {
        checkOpen();
        PgStatement statement = new PgStatement(this);
        open.add(statement);
        return statement;
    }

    @Override
    public PreparedStatement prepareStatement(String sql) throws SQLException {
        checkOpen();
        Idle idle = takePlan(sql);
        PgPreparedStatement statement = idle == null
                ? new PgPreparedStatement(this, sql,
                        "zl_" + statementCounter.incrementAndGet(), null)
                : new PgPreparedStatement(this, sql, idle.name(), idle.described());
        open.add(statement);
        return statement;
    }

    @Override
    public Statement createStatement(int resultSetType, int resultSetConcurrency)
            throws SQLException {
        requireForwardReadOnly(resultSetType, resultSetConcurrency);
        return createStatement();
    }

    @Override
    public Statement createStatement(int resultSetType, int resultSetConcurrency,
                                     int resultSetHoldability) throws SQLException {
        requireForwardReadOnly(resultSetType, resultSetConcurrency);
        return createStatement();
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int resultSetType,
                                              int resultSetConcurrency) throws SQLException {
        requireForwardReadOnly(resultSetType, resultSetConcurrency);
        return prepareStatement(sql);
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int resultSetType,
                                              int resultSetConcurrency, int resultSetHoldability)
            throws SQLException {
        requireForwardReadOnly(resultSetType, resultSetConcurrency);
        return prepareStatement(sql);
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int autoGeneratedKeys)
            throws SQLException {
        if (autoGeneratedKeys == Statement.NO_GENERATED_KEYS) {
            return prepareStatement(sql);
        }
        return prepareStatement(sql, (String[]) null);
    }

    /**
     * The keys by name - {@code returning} under the hood.
     *
     * <p>Every {@code @GeneratedValue} entity and every {@code save()} of
     * Spring Data goes through here, which is why refusing it meant the
     * library did not work with the framework almost everybody uses.
     */
    @Override
    public PreparedStatement prepareStatement(String sql, String[] columnNames)
            throws SQLException {
        checkOpen();
        PgPreparedStatement statement = (PgPreparedStatement) prepareStatement(
                PgStatement.withReturning(sql, columnNames));
        statement.expectGeneratedKeys();
        return statement;
    }

    /**
     * By column number - refused, and with the reason.
     *
     * <p>The numbers refer to the columns of the table, and a client cannot
     * know them without asking the server first. Naming them is one word more
     * and cannot be misunderstood.
     */
    @Override
    public PreparedStatement prepareStatement(String sql, int[] columnIndexes)
            throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "generated keys by column number are not supported - name the columns "
                + "instead: prepareStatement(sql, new String[] {\"id\"})");
    }


    @Override
    public CallableStatement prepareCall(String sql) throws SQLException {
        checkOpen();
        CallSyntax call = CallSyntax.parse(sql);
        // The plan cache is keyed by the statement that goes to the server,
        // not by what the caller wrote - two callers writing the same call
        // with and without braces share one plan, which is right.
        String statement = PgCallableStatement.statementFor(call);
        Idle idle = takePlan(statement);
        PgCallableStatement prepared = idle == null
                ? new PgCallableStatement(this, call,
                        "zl_" + statementCounter.incrementAndGet(), null)
                : new PgCallableStatement(this, call, idle.name(), idle.described());
        open.add(prepared);
        return prepared;
    }

    @Override
    public CallableStatement prepareCall(String sql, int a, int b) throws SQLException {
        return prepareCall(sql);
    }

    @Override
    public CallableStatement prepareCall(String sql, int a, int b, int c) throws SQLException {
        return prepareCall(sql);
    }

    private void requireForwardReadOnly(int type, int concurrency) throws SQLException {
        if (type != ResultSet.TYPE_FORWARD_ONLY || concurrency != ResultSet.CONCUR_READ_ONLY) {
            throw new SQLFeatureNotSupportedException(
                    "seclume result sets are forward-only and read-only");
        }
    }

    // ---- transactions ----------------------------------------------------

    @Override
    public boolean getAutoCommit() throws SQLException {
        checkOpen();
        return autoCommit;
    }

    @Override
    public void setAutoCommit(boolean value) throws SQLException {
        checkOpen();
        if (value == autoCommit) {
            return;
        }
        if (!value) {
            // Announced, not sent: the BEGIN rides along with the next
            // statement instead of costing a round trip of its own.
            session.beginLater();
        } else {
            commitPending();
        }
        autoCommit = value;
    }

    @Override
    public void commit() throws SQLException {
        checkOpen();
        requireManualCommit("commit");
        // Whatever the block still holds belongs to this transaction.
        session.flushPipeline();
        commitPending();
        // The next transaction opens with its first statement, not here.
        session.beginLater();
    }

    @Override
    public void rollback() throws SQLException {
        checkOpen();
        requireManualCommit("rollback");
        // Sent, so that a failure in the block is seen before it is discarded.
        session.flushPipeline();
        rollbackPending();
        session.beginLater();
    }

    /**
     * Commits - unless the transaction was never opened.
     *
     * <p>A {@code BEGIN} that is still waiting for its statement means nothing
     * happened yet, and committing nothing costs a round trip for nothing.
     */
    private void commitPending() throws SQLException {
        // A transaction that was announced but never opened has nothing in it.
        // Committing it would be a round trip for nothing - and leaving the
        // announcement standing would open one that nobody ever closes.
        if (session.cancelPendingBegin()) {
            return;
        }
        session.execute("commit");
    }

    private void rollbackPending() throws SQLException {
        if (session.cancelPendingBegin()) {
            return;
        }
        // Whatever is still queued belonged to this transaction, and after a
        // failed statement the server refuses it anyway - it would fail as a
        // group and hide the rollback behind its own error.
        session.discardPending();
        session.execute("rollback");
    }

    private void requireManualCommit(String what) throws SQLException {
        if (autoCommit) {
            throw new SQLException("cannot " + what
                    + " while auto-commit is on - call setAutoCommit(false) first");
        }
    }

    @Override
    public int getTransactionIsolation() throws SQLException {
        checkOpen();
        return isolation;
    }

    @Override
    public void setTransactionIsolation(int level) throws SQLException {
        checkOpen();
        if (level == isolation) {
            return;                              // nothing to say to the server
        }

        String name = switch (level) {
            case TRANSACTION_READ_COMMITTED -> "read committed";
            case TRANSACTION_REPEATABLE_READ -> "repeatable read";
            case TRANSACTION_SERIALIZABLE -> "serializable";
            // PostgreSQL knows read uncommitted only as a synonym for read
            // committed; refusing it here would be stricter than the server.
            case TRANSACTION_READ_UNCOMMITTED -> "read uncommitted";
            default -> throw new SQLException("unknown transaction isolation level: " + level);
        };
        // Rides along with the next statement - see PgSession.runLater.
        session.runLater("set session characteristics as transaction isolation level " + name);
        isolation = level;
    }

    @Override
    public boolean isReadOnly() throws SQLException {
        checkOpen();
        return readOnly;
    }

    @Override
    public void setReadOnly(boolean value) throws SQLException {
        checkOpen();
        if (value != readOnly) {
            session.runLater("set session characteristics as transaction "
                    + (value ? "read only" : "read write"));
            readOnly = value;
        }
    }

    @Override
    public Savepoint setSavepoint() throws SQLException {
        throw savepoints();
    }

    @Override
    public Savepoint setSavepoint(String name) throws SQLException {
        throw savepoints();
    }

    @Override
    public void rollback(Savepoint savepoint) throws SQLException {
        throw savepoints();
    }

    @Override
    public void releaseSavepoint(Savepoint savepoint) throws SQLException {
        throw savepoints();
    }

    private static SQLFeatureNotSupportedException savepoints() {
        return new SQLFeatureNotSupportedException(
                "seclume does not implement savepoints yet");
    }

    // ---- state -----------------------------------------------------------

    @Override
    public DatabaseMetaData getMetaData() throws SQLException {
        checkOpen();
        return new PgDatabaseMetaData(this);
    }

    @Override
    public String getCatalog() throws SQLException {
        checkOpen();
        return session.database();
    }

    @Override
    public void setCatalog(String catalog) throws SQLException {
        checkOpen();
        // PostgreSQL cannot switch the database of a connection; swallowing
        // that silently would be a lie.
        throw new SQLFeatureNotSupportedException(
                "PostgreSQL cannot switch databases on an open connection - open a new one");
    }

    @Override
    public String getSchema() throws SQLException {
        try (Statement statement = createStatement();
             ResultSet result = statement.executeQuery("select current_schema()")) {
            return result.next() ? result.getString(1) : null;
        }
    }

    @Override
    public void setSchema(String schema) throws SQLException {
        checkOpen();
        if (schema == null || !schema.matches("[A-Za-z_][A-Za-z0-9_$]*")) {
            throw new SQLException("not a plain schema name: " + schema);
        }
        session.execute("set search_path to " + schema);
    }

    @Override
    public int getHoldability() {
        return ResultSet.CLOSE_CURSORS_AT_COMMIT;
    }

    @Override
    public void setHoldability(int holdability) throws SQLException {
        if (holdability != ResultSet.CLOSE_CURSORS_AT_COMMIT) {
            throw new SQLFeatureNotSupportedException(
                    "seclume closes result sets when the transaction ends");
        }
    }

    @Override
    public boolean isValid(int timeout) {
        if (closed || !session.isOpen()) {
            return false;
        }
        try {
            session.execute("select 1");
            return true;
        } catch (SQLException e) {
            return false;
        }
    }

    /**
     * How often this connection has waited for the server.
     *
     * <p>See {@link space.seclume.RoundTrips}: the number does not
     * depend on the network, so it says the same thing on a laptop and in
     * production.
     */
    @Override
    public long roundTrips() {
        return session.roundTrips();
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            for (PgStatement statement : List.copyOf(open)) {
                statement.close();
            }
            open.clear();
            if (spare != null) {
                // The one block that was kept for the next statement - here it
                // really does go back, and deterministically.
                spare.close();
                spare = null;
            }
            session.close();
        }
    }

    @Override
    public boolean isClosed() {
        return closed || !session.isOpen();
    }

    void checkOpen() throws SQLException {
        if (isClosed()) {
            throw new SQLException("this connection is closed", "08003");
        }
    }

    @Override
    public SQLWarning getWarnings() {
        return null;
    }

    @Override
    public void clearWarnings() {
        // Warnings are not collected, so there is nothing to clear.
    }

    @Override
    public String nativeSQL(String sql) throws SQLException {
        checkOpen();
        return sql;
    }

    @Override
    public Properties getClientInfo() {
        return new Properties();
    }

    @Override
    public String getClientInfo(String name) {
        return null;
    }

    @Override
    public void setClientInfo(String name, String value) throws SQLClientInfoException {
        throw new SQLClientInfoException("seclume does not set client info properties", Map.of());
    }

    @Override
    public void setClientInfo(Properties properties) throws SQLClientInfoException {
        throw new SQLClientInfoException("seclume does not set client info properties", Map.of());
    }

    @Override
    public Map<String, Class<?>> getTypeMap() {
        return Map.of();
    }

    @Override
    public void setTypeMap(Map<String, Class<?>> map) throws SQLException {
        if (map != null && !map.isEmpty()) {
            throw new SQLFeatureNotSupportedException("seclume has no custom type map");
        }
    }

    @Override
    public void abort(Executor executor) {
        close();
    }

    @Override
    public void setNetworkTimeout(Executor executor, int milliseconds) throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "seclume does not change the socket timeout after connecting");
    }

    @Override
    public int getNetworkTimeout() {
        return 0;
    }

    @Override
    public Clob createClob() throws SQLException {
        throw large("CLOB");
    }

    @Override
    public Blob createBlob() throws SQLException {
        throw large("BLOB");
    }

    @Override
    public NClob createNClob() throws SQLException {
        throw large("NCLOB");
    }

    @Override
    public SQLXML createSQLXML() throws SQLException {
        throw large("SQLXML");
    }

    @Override
    public Array createArrayOf(String typeName, Object[] elements) throws SQLException {
        throw large("ARRAY");
    }

    @Override
    public Struct createStruct(String typeName, Object[] attributes) throws SQLException {
        throw large("STRUCT");
    }

    private static SQLFeatureNotSupportedException large(String type) {
        return new SQLFeatureNotSupportedException("seclume does not create " + type + " values");
    }

    // ---- the pipeline block ---------------------------------------------

    /**
     * See {@link space.seclume.Pipeline} - this is the driver side.
     *
     * <p>Refused in auto-commit, and not out of pedantry: each statement would
     * commit on its own, and a failure in the third would leave the first two
     * standing. A half-written unit of work is worse than a slow one.
     */
    @Override
    public void beginPipeline() throws SQLException {
        checkOpen();
        if (getAutoCommit()) {
            throw new SQLException("a pipeline block needs a transaction - in auto-commit "
                    + "every statement would commit on its own, and a failure in the middle "
                    + "would leave the ones before it standing. Call setAutoCommit(false) "
                    + "first.", "25000");
        }
        session.beginPipeline();
    }

    @Override
    public long[] endPipeline() throws SQLException {
        checkOpen();
        return session.endPipeline();
    }

    @Override
    public boolean isPipelining() {
        return session.isPipelining();
    }

    @Override
    public void flushPipeline() throws SQLException {
        checkOpen();
        session.flushPipeline();
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) {
            return iface.cast(this);
        }
        if (iface.isInstance(session)) {
            return iface.cast(session);
        }
        throw new SQLException("not a wrapper for " + iface.getName());
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) {
        return iface.isInstance(this) || iface.isInstance(session);
    }
}
