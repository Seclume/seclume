package space.seclume.oracle.jdbc;

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

import space.seclume.oracle.OracleSession;

/**
 * A JDBC connection on top of an {@link OracleSession}.
 *
 * <p>The connection holds no password. It needed one when it was opened, and
 * that one lived in native memory which was zeroed afterwards.
 *
 * <p>Bind variables go over as bind variables - see
 * {@link OraPreparedStatement}. A value never enters the statement text, so
 * SQL injection is not something warded off on this path; it does not exist
 * here.
 */
public final class OraConnection implements Connection, RoundTrips, Pipelined {

    private final OracleSession session;
    private final String url;
    private final List<OraStatement> open = new ArrayList<>();
    private boolean autoCommit = true;
    private boolean readOnly;
    private boolean closed;
    private int isolation = TRANSACTION_READ_COMMITTED;
    private int savepointCounter;

    OraConnection(OracleSession session, String url) {
        this.session = session;
        this.url = url;
    }

    /** A result block a closed statement left behind - see takeSpareBlock. */
    private OraResultBlock spare;

    OracleSession session() throws SQLException {
        checkOpen();
        return session;
    }

    String url() {
        return url;
    }

    void forget(OraStatement statement) {
        open.remove(statement);
    }


    /**
     * One spare result block per connection, kept instead of freed.
     *
     * <p>This was the single most expensive thing in the whole
     * driver under load: the block's memory lives in a <b>shared</b> arena -
     * it has to, because a pooled connection is opened on one thread and
     * closed on another - and closing a shared arena makes the JVM coordinate
     * with every other thread. Half of all runnable time went into
     * {@code closeScope0} while eight threads did nothing but borrow, query
     * and return, because every {@code createStatement}/{@code close} pair
     * freed a block. Keeping one turned 158 us per borrow-query-return into
     * 63 - see the performance notes.
     *
     * <p>At most one is kept, so a connection's memory stays bounded, and it
     * is freed for good when the connection closes - deterministically, as
     * everything in this library is.
     */
    OraResultBlock takeSpareBlock() {
        OraResultBlock block = spare;
        spare = null;
        return block;
    }

    /** Takes a block back from a statement that is closing. */
    void recycleBlock(OraResultBlock block) {
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
        OraStatement statement = new OraStatement(this);
        open.add(statement);
        return statement;
    }

    /**
     * A prepared statement - and with Oracle that is no extra round trip: the
     * text and the values go over together, and the server keeps the plan
     * under the text. The reason to use one is that the values never enter the
     * statement text.
     */
    @Override
    public PreparedStatement prepareStatement(String sql) throws SQLException {
        checkOpen();
        OraPreparedStatement statement = new OraPreparedStatement(this, sql);
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
    public PreparedStatement prepareStatement(String sql, int a, int b) throws SQLException {
        return prepareStatement(sql);
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int a, int b, int c)
            throws SQLException {
        return prepareStatement(sql);
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int autoGeneratedKeys)
            throws SQLException {
        if (autoGeneratedKeys == Statement.NO_GENERATED_KEYS) {
            return prepareStatement(sql);
        }
        throw new SQLFeatureNotSupportedException(
                "Oracle hands generated keys back through a 'returning ... into' clause, "
                + "and that clause has to name the columns - so name them: "
                + "prepareStatement(sql, new String[] {\"id\"})");
    }

    /**
     * The keys by name - {@code returning ... into} under the hood.
     *
     * <p>This is the form Hibernate uses for Oracle, and it is the only one
     * that can work: the server needs to know which columns to write back.
     */
    @Override
    public PreparedStatement prepareStatement(String sql, String[] columnNames)
            throws SQLException {
        checkOpen();
        OraPreparedStatement statement = (OraPreparedStatement) prepareStatement(sql);
        statement.wantGeneratedKeys(columnNames);
        return statement;
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int[] columnIndexes)
            throws SQLException {
        return prepareStatement(sql);
    }

    @Override
    public CallableStatement prepareCall(String sql) throws SQLException {
        checkOpen();
        OraCallableStatement statement =
                new OraCallableStatement(this, CallSyntax.parse(sql));
        open.add(statement);
        return statement;
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

    /**
     * Oracle is always inside a transaction: every statement opens one, and it
     * runs until a commit or a rollback. "Auto-commit" therefore means
     * committing after each statement, which is a flag in the execute call -
     * and that flag is not set yet. Until it is, only the manual mode is
     * honest.
     */
    @Override
    public void setAutoCommit(boolean value) throws SQLException {
        checkOpen();
        if (value == autoCommit) {
            return;
        }
        // Leaving a transaction open and switching auto-commit on would commit
        // it by surprise on the next statement; JDBC says commit here, and
        // that is the only reading that does not lose work.
        if (value) {
            // Commits only if something actually ran - see OracleSession.
            session.commit();
        }
        autoCommit = value;
        session.setAutoCommit(value);
    }

    @Override
    public void commit() throws SQLException {
        checkOpen();
        session.commit();
    }

    @Override
    public void rollback() throws SQLException {
        checkOpen();
        session.rollback();
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
            case TRANSACTION_SERIALIZABLE -> "serializable";
            default -> throw new SQLException(
                    "Oracle knows only READ COMMITTED and SERIALIZABLE, not level " + level);
        };
        session.query("set transaction isolation level " + name, null);
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
            session.query("set transaction " + (value ? "read only" : "read write"), null);
            readOnly = value;
        }
    }

    @Override
    public Savepoint setSavepoint() throws SQLException {
        return setSavepoint("zl_" + (++savepointCounter));
    }

    @Override
    public Savepoint setSavepoint(String name) throws SQLException {
        checkOpen();
        String safe = requirePlainName(name);
        session.query("savepoint " + safe, null);
        return new NamedSavepoint(safe);
    }

    @Override
    public void rollback(Savepoint savepoint) throws SQLException {
        checkOpen();
        session.query("rollback to savepoint "
                + requirePlainName(savepoint.getSavepointName()), null);
    }

    /** Oracle cannot release a savepoint; it lives until the transaction ends. */
    @Override
    public void releaseSavepoint(Savepoint savepoint) throws SQLException {
        checkOpen();
        requirePlainName(savepoint.getSavepointName());
    }

    /** A savepoint name goes into the SQL text; it has to be an identifier. */
    private static String requirePlainName(String name) throws SQLException {
        if (name == null || !name.matches("[A-Za-z_][A-Za-z0-9_$#]*")) {
            throw new SQLException("not a plain name: " + name);
        }
        return name;
    }

    private record NamedSavepoint(String name) implements Savepoint {

        @Override
        public int getSavepointId() throws SQLException {
            throw new SQLFeatureNotSupportedException("this savepoint has a name, not an id");
        }

        @Override
        public String getSavepointName() {
            return name;
        }
    }

    // ---- state -----------------------------------------------------------

    @Override
    public DatabaseMetaData getMetaData() throws SQLException {
        checkOpen();
        return new OraDatabaseMetaData(this);
    }

    /** Oracle has no catalogs - the schema is the unit of naming. */
    @Override
    public String getCatalog() throws SQLException {
        checkOpen();
        return null;
    }

    @Override
    public void setCatalog(String catalog) throws SQLException {
        throw new SQLFeatureNotSupportedException("Oracle has no catalogs");
    }

    @Override
    public String getSchema() throws SQLException {
        try (Statement statement = createStatement();
             ResultSet result = statement.executeQuery(
                     "select sys_context('userenv','current_schema') from dual")) {
            return result.next() ? result.getString(1) : null;
        }
    }

    @Override
    public void setSchema(String schema) throws SQLException {
        checkOpen();
        session.query("alter session set current_schema = " + requirePlainName(schema), null);
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
            session.query("select 1 from dual", null);
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
            for (OraStatement statement : List.copyOf(open)) {
                statement.close();
            }
            open.clear();
            if (spare != null) {
                // The one block kept for the next statement - here it really
                // does go back, and deterministically.
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

    /**
     * Puts the session back into a known state - what a pool needs when a
     * connection comes back. An open transaction is rolled back; leaving it
     * would hand the next borrower somebody else's locks.
     */
    public void reset() throws SQLException {
        checkOpen();
        session.query("rollback", null);
        autoCommit = true;
        readOnly = false;
        isolation = TRANSACTION_READ_COMMITTED;
    }

    /**
     * An empty {@code Clob} to fill and hand to a statement.
     *
     * <p>It keeps its contents here rather than on the server. That is what
     * the method promises - „a Clob object with no data" that can be filled and
     * passed to a {@code PreparedStatement} - and it is what frameworks use it
     * for. {@code setClob} then sends the value as an ordinary parameter.
     *
     * <p>A server-side <b>temporary</b> LOB, the kind that goes to a PL/SQL
     * procedure, is a different thing and not this. The groundwork for it -
     * the operation codes and the fact that a temporary locator is 38 bytes
     * rather than 112 - is in place.
     */
    @Override
    public Clob createClob() {
        return OraLocalLob.clob();
    }

    @Override
    public Blob createBlob() {
        return OraLocalLob.blob();
    }

    @Override
    public NClob createNClob() {
        return OraLocalLob.clob();
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
     * From here on, an update nobody is waiting for is sent without waiting.
     *
     * <p>{@link space.seclume.Pipeline} exists so that an application can
     * write a unit of work once and have it cost one trip where the protocol
     * allows it. <b>Oracle allows a different shape of it than SQL Server
     * does</b>, and the difference is worth knowing: TDS carries several calls
     * in one message, so the round trips themselves disappear. Oracle numbers
     * every call and answers each one, so the calls still travel separately -
     * what the block removes is the <b>waiting between them</b>.
     *
     * <p>That distinction is invisible on a loopback connection and decisive
     * over a real one. Measured through a relay adding ten milliseconds each
     * way - an ordinary distance between an application server and its
     * database - eight inserts took <b>199 ms one at a time and 46 ms in a
     * block</b>. The round trip counter reports the same number either way,
     * because it counts answers read and not time spent; that is a limit of
     * the counter, not of the block.
     *
     * <p><b>What is not buffered</b>, because it cannot be: a query, anything
     * asking for generated keys, and a statement with an open cursor. Each of
     * those sends what is outstanding and reads its answers first, which is
     * what keeps an answer from being handed to the wrong caller.
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
