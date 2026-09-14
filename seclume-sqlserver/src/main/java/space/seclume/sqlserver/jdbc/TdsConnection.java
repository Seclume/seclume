package space.seclume.sqlserver.jdbc;

import space.seclume.Pipelined;
import space.seclume.RoundTrips;
import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;
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

import space.seclume.sqlserver.tds.TdsSession;

/**
 * A JDBC connection on top of a {@link TdsSession}.
 *
 * <p>The connection holds no password. It needed one when it was opened, and
 * that one lived in native memory which was zeroed afterwards.
 *
 * <p>Transactions work differently here than in the other drivers. SQL Server
 * commits every statement on its own unless one says otherwise, and JDBC's
 * {@code setAutoCommit(false)} maps onto {@code implicit_transactions on}: the
 * server then opens a transaction by itself at the next statement and keeps it
 * open until {@code commit} or {@code rollback}. That is also why the session
 * tracks the transaction descriptor - the server hands one out and expects it
 * back with every request.
 */
public final class TdsConnection implements Connection, RoundTrips, Pipelined {

    private final TdsSession session;
    private final String url;
    private final List<TdsStatement> open = new ArrayList<>();
    private boolean autoCommit = true;
    private boolean readOnly;
    private boolean closed;
    private int isolation = TRANSACTION_READ_COMMITTED;
    private int savepointCounter;

    TdsConnection(TdsSession session, String url) {
        this.session = session;
        this.url = url;
    }

    /** A result block a closed statement left behind - see takeSpareBlock. */
    private TdsResultBlock spare;

    TdsSession session() throws SQLException {
        checkOpen();
        return session;
    }

    String url() {
        return url;
    }

    void forget(TdsStatement statement) {
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
     * freed a block. Keeping one turned 158 us per borrow-query-return into
     * 63 - see docs/performance.md.
     *
     * <p>At most one is kept, so a connection's memory stays bounded, and it
     * is freed for good when the connection closes - deterministically, as
     * everything in this library is.
     */
    TdsResultBlock takeSpareBlock() {
        TdsResultBlock block = spare;
        spare = null;
        return block;
    }

    /** Takes a block back from a statement that is closing. */
    void recycleBlock(TdsResultBlock block) {
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
        TdsStatement statement = new TdsStatement(this);
        open.add(statement);
        return statement;
    }

    @Override
    public PreparedStatement prepareStatement(String sql) throws SQLException {
        checkOpen();
        TdsPreparedStatement statement = new TdsPreparedStatement(this, sql);
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
        // The key comes from scope_identity() afterwards; there is nothing to
        // request here.
        return prepareStatement(sql);
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int[] columnIndexes)
            throws SQLException {
        return prepareStatement(sql);
    }

    @Override
    public PreparedStatement prepareStatement(String sql, String[] columnNames)
            throws SQLException {
        return prepareStatement(sql);
    }

    @Override
    public CallableStatement prepareCall(String sql) throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "seclume has no CallableStatement - call a procedure with "
                + "'exec proc ?, ?' through a PreparedStatement; OUT parameters "
                + "are not supported");
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
     * SQL Server has no {@code autocommit} switch - it has the opposite one.
     * With {@code implicit_transactions on} the server opens a transaction at
     * the next statement all by itself and leaves it open.
     */
    @Override
    public void setAutoCommit(boolean value) throws SQLException {
        checkOpen();
        if (value == autoCommit) {
            return;
        }
        if (value && session.transactionDescriptor() != 0) {
            // Switching back with a transaction still open would silently
            // leave it hanging until the connection is closed.
            session.execute("commit tran");
        }
        // Rides along with the next statement: on its own this is a round
        // trip in which the database does nothing, and a framework sends it
        // twice per transaction.
        session.runLater("set implicit_transactions " + (value ? "off" : "on"));
        autoCommit = value;
    }

    @Override
    public void commit() throws SQLException {
        checkOpen();
        requireManualCommit("commit");
        if (session.hasPending()) {
            // The switch to manual mode never went out, so nothing ran inside
            // a transaction and there is nothing to commit. Sending one anyway
            // would be a round trip for nothing - but the setting still has to
            // stand for what comes next, so it stays pending.
            return;
        }
        session.execute("if @@trancount > 0 commit tran");
    }

    @Override
    public void rollback() throws SQLException {
        checkOpen();
        requireManualCommit("rollback");
        session.execute("if @@trancount > 0 rollback tran");
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
            case TRANSACTION_READ_UNCOMMITTED -> "read uncommitted";
            case TRANSACTION_READ_COMMITTED -> "read committed";
            case TRANSACTION_REPEATABLE_READ -> "repeatable read";
            case TRANSACTION_SERIALIZABLE -> "serializable";
            default -> throw new SQLException("unknown transaction isolation level: " + level);
        };
        session.runLater("set transaction isolation level " + name);
        isolation = level;
    }

    @Override
    public boolean isReadOnly() throws SQLException {
        checkOpen();
        return readOnly;
    }

    /**
     * Remembered, but not sent: SQL Server has no read-only session. There is
     * {@code ApplicationIntent=ReadOnly} at login, which routes to a replica -
     * that is a different thing, and pretending otherwise would be a lie about
     * what is enforced.
     */
    @Override
    public void setReadOnly(boolean value) throws SQLException {
        checkOpen();
        this.readOnly = value;
    }

    @Override
    public Savepoint setSavepoint() throws SQLException {
        return setSavepoint("zl_" + (++savepointCounter));
    }

    @Override
    public Savepoint setSavepoint(String name) throws SQLException {
        checkOpen();
        requireManualCommit("set a savepoint");
        String safe = requirePlainName(name);
        session.execute("save tran " + safe);
        return new NamedSavepoint(safe);
    }

    @Override
    public void rollback(Savepoint savepoint) throws SQLException {
        checkOpen();
        session.execute("rollback tran " + requirePlainName(savepoint.getSavepointName()));
    }

    /**
     * SQL Server cannot release a savepoint - it lives until the transaction
     * ends. Accepting the call and doing nothing is the honest behaviour here:
     * JDBC allows a savepoint to become invalid, and nothing is claimed.
     */
    @Override
    public void releaseSavepoint(Savepoint savepoint) throws SQLException {
        checkOpen();
        requirePlainName(savepoint.getSavepointName());
    }

    /** A savepoint name goes into the SQL text; it has to be an identifier. */
    private static String requirePlainName(String name) throws SQLException {
        if (name == null || !name.matches("[A-Za-z_][A-Za-z0-9_$]*")) {
            throw new SQLException("not a plain savepoint name: " + name);
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
        return new TdsDatabaseMetaData(this);
    }

    /** SQL Server calls the database the catalog, and it has schemas below it. */
    @Override
    public String getCatalog() throws SQLException {
        checkOpen();
        return session.database();
    }

    @Override
    public void setCatalog(String catalog) throws SQLException {
        checkOpen();
        if (catalog == null || !catalog.matches("[A-Za-z0-9_$]+")) {
            throw new SQLException("not a plain database name: " + catalog);
        }
        session.execute("use [" + catalog + "]");
    }

    @Override
    public String getSchema() throws SQLException {
        try (Statement statement = createStatement();
             ResultSet result = statement.executeQuery("select schema_name()")) {
            return result.next() ? result.getString(1) : null;
        }
    }

    /**
     * The default schema belongs to the user, not to the session - there is no
     * {@code set schema}. Whoever wants another one qualifies the table.
     */
    @Override
    public void setSchema(String schema) throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "SQL Server has no 'set schema' - the default schema belongs to the user");
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
            for (TdsStatement statement : List.copyOf(open)) {
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
        session.execute("if @@trancount > 0 rollback tran; set implicit_transactions off");
        autoCommit = true;
        readOnly = false;
        isolation = TRANSACTION_READ_COMMITTED;
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
     * The block is allowed here and saves nothing - yet.
     *
     * <p>{@link space.seclume.Pipeline} exists so that an
     * application can write a unit of work once and have it cost one round
     * trip where the protocol allows it. SQL Server answers every call
     * of its own accord, so there is nothing to hold back: the statements go
     * out as they always did and report their counts as they always did.
     *
     * <p>Saying so is the point. A block that silently pretends to bundle
     * would be worse than one that admits it does not - and the code stays
     * portable either way.
     */
    @Override
    public void beginPipeline() throws SQLException {
        checkOpen();
    }

    @Override
    public long[] endPipeline() throws SQLException {
        checkOpen();
        return new long[0]; // seclume-allow: no counts, because nothing was held back
    }

    @Override
    public boolean isPipelining() {
        return false;
    }

    @Override
    public void flushPipeline() throws SQLException {
        checkOpen();
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
