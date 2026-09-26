package space.seclume.mysql.jdbc;

import space.seclume.Pipelined;
import space.seclume.RoundTrips;
import space.seclume.Secured;
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

import space.seclume.mysql.MySession;

/**
 * A JDBC connection on top of a {@link MySession}.
 *
 * <p>The connection holds no password. It needed one when it was opened, and
 * that one lived in native memory which was zeroed afterwards.
 *
 * <p>Unlike with PostgreSQL, the database can be switched here ({@code USE})
 * and a savepoint can be set - MySQL can do both, so this driver can too.
 */
public final class MyConnection implements Connection, space.seclume.internal.jdbc.Fronted, RoundTrips, Pipelined, Secured, space.seclume.Flight,
        space.seclume.SessionReset, space.seclume.ServerCapacity, space.seclume.ServerIdleLimit,
        space.seclume.SessionContext,
        space.seclume.OpenStatements {

    /** The handle in front of this connection, while there is one - see {@link space.seclume.internal.jdbc.Fronted}. */
    private volatile Connection front;

    @Override
    public void front(Connection handle) {
        this.front = handle;
    }

    /** What a statement or metadata object made now names as its connection. */
    Connection frontOrSelf() {
        Connection handle = front;
        return handle != null ? handle : this;
    }

    /** Whether statements record where they were made - see OpenStatements. */
    private volatile boolean traceStatements;

    /** A statement's birthplace, when asked for; nothing otherwise, which is free. */
    StackTraceElement[] creationTrace() {
        return traceStatements ? new Throwable().getStackTrace() : null;
    }

    @Override
    public void traceStatements(boolean on) {
        traceStatements = on;
    }

    @Override
    public java.util.List<space.seclume.OpenStatements.Opened> openStatements() {
        java.util.List<space.seclume.OpenStatements.Opened> opened = new java.util.ArrayList<>();
        for (MyStatement statement : new java.util.ArrayList<>(open)) {
            String sql = statement.lastSql();
            opened.add(new space.seclume.OpenStatements.Opened(statement,
                    sql == null ? null : space.seclume.QueryFingerprint.of(sql),
                    statement.createdAt));
        }
        return opened;
    }

    /** The server's connection limit and use - see {@link space.seclume.ServerCapacity}. */
    @Override
    public space.seclume.ServerCapacity.Capacity capacity() throws SQLException {
        checkOpen();
        return space.seclume.internal.jdbc.Capacities.ask(this,
                "select @@max_connections",
                "select variable_value from performance_schema.global_status where variable_name = 'Threads_connected'");
    }


    /** The server's idle limit - {@code wait_timeout} of this session, in seconds - eight hours unless somebody changed it. */
    @Override
    public java.time.Duration idleLimit() throws SQLException {
        checkOpen();
        return space.seclume.internal.jdbc.Capacities.idleLimit(this,
                "select @@session.wait_timeout",
                java.time.Duration.ofSeconds(1));
    }

    /** See {@link space.seclume.SessionContext}: a user variable, with the next statement. */
    @Override
    public void setSessionContext(String name, String value) throws SQLException {
        checkOpen();
        space.seclume.internal.jdbc.ContextValues.check(name, value);
        String variable = "@" + name.replace('.', '_');
        String literal = space.seclume.internal.jdbc.ContextValues.hexUtf8(value);
        sessionState.note("set " + variable + " = " + literal);
        session.runLater(variable, literal);
    }

    /**
     * {@code LOAD DATA LOCAL INFILE ... INTO TABLE ...}, fed from {@code data} -
     * MySQL's bulk import. Needs {@code loadDataLocal=true} on the URL and
     * {@code local_infile=ON} on the server. The file name in the statement
     * is never opened: the server gets {@code data} and nothing else, and a
     * server that asks for a file at any other time gets an empty one.
     *
     * <pre>
     *   MyConnection my = connection.unwrap(MyConnection.class);
     *   long rows = my.loadData("load data local infile 'orders.csv' into table orders "
     *           + "fields terminated by ','", csvStream);
     * </pre>
     *
     * @return the rows loaded
     */
    public long loadData(String sql, java.io.InputStream data) throws SQLException {
        checkOpen();
        return session.loadData(sql, data);
    }

    /** What statements set beyond the transaction - see {@link space.seclume.SessionReset}. */
    private final space.seclume.internal.jdbc.SessionState sessionState =
            new space.seclume.internal.jdbc.SessionState();

    /** For the statements: each notes its text here. */
    space.seclume.internal.jdbc.SessionState sessionState() {
        return sessionState;
    }

    @Override
    public boolean sessionStateChanged() {
        return sessionState.changed();
    }

    /**
     * {@code COM_RESET_CONNECTION}: user variables, temporary tables, session
     * settings and prepared statements, back to what the login gave. The
     * isolation and read-only the connection has are sent again when they are
     * not the login's.
     */
    @Override
    public boolean resetSessionState() throws SQLException {
        checkOpen();
        if (!sessionState.changed()) {
            return true;
        }
        if (!autoCommit) {
            return false;
        }
        int wantedIsolation = isolation;
        boolean wantedReadOnly = readOnly;
        session.dropPendingVariables();
        reset();
        isolation = TRANSACTION_REPEATABLE_READ;
        if (wantedIsolation != isolation) {
            setTransactionIsolation(wantedIsolation);
        }
        if (wantedReadOnly) {
            setReadOnly(true);
        }
        return true;
    }

    private final MySession session;
    private final String url;
    private final List<MyStatement> open = new ArrayList<>();
    private boolean autoCommit = true;
    /** Batches of plain inserts as multi-row inserts - {@code rewriteBatchedInserts}. */
    private boolean rewriteBatchedInserts;
    private boolean readOnly;
    private boolean closed;
    private int isolation = TRANSACTION_REPEATABLE_READ;
    private int savepointCounter;

    /**
     * A JDBC connection on a session this process did not open - what an
     * application holds, put back on a session that was handed over.
     *
     * <p>{@code facts} are what the giving connection knew about itself (see
     * {@link space.seclume.internal.jdbc.ConnectionFacts}); the server session
     * carries everything else.
     */
    public static java.sql.Connection resume(MySession session,
            space.seclume.internal.jdbc.ConnectionFacts facts) {
        MyConnection connection = new MyConnection(session, "jdbc:seclume:mysql:resumed");
        connection.autoCommit = facts.autoCommit();
        connection.readOnly = facts.readOnly();
        connection.isolation = facts.isolation();
        connection.savepointCounter = facts.savepoints();
        return connection;
    }

    /**
     * What this connection knows about itself, for whoever takes its session
     * over - read it <b>before</b> the session is detached.
     */
    public space.seclume.internal.jdbc.ConnectionFacts facts() {
        return new space.seclume.internal.jdbc.ConnectionFacts(autoCommit, readOnly, isolation,
                0, savepointCounter);
    }

    MyConnection(MySession session, String url) {
        this.session = session;
        this.url = url;
    }

    /** A result block a closed statement left behind - see takeSpareBlock. */
    private MyResultBlock spare;

    MySession session() throws SQLException {
        checkOpen();
        return session;
    }

    /**
     * Whether a tinyint(1) is a boolean on this connection.
     *
     * <p>Without the open check the other accessor makes: this is asked while
     * a result block is being built, where the connection is demonstrably open
     * and a checked exception would only travel.
     */
    boolean tinyInt1isBit() {
        return session.tinyInt1isBit();
    }

    String url() {
        return url;
    }

    void forget(MyStatement statement) {
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
     * 63 - see the performance notes.
     *
     * <p>At most one is kept, so a connection's memory stays bounded, and it
     * is freed for good when the connection closes - deterministically, as
     * everything in this library is.
     */
    MyResultBlock takeSpareBlock() {
        MyResultBlock block = spare;
        spare = null;
        return block;
    }

    /** Takes a block back from a statement that is closing. */
    void recycleBlock(MyResultBlock block) {
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
        MyStatement statement = new MyStatement(this);
        open.add(statement);
        return statement;
    }

    @Override
    public PreparedStatement prepareStatement(String sql) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.MYSQL);
        checkOpen();
        MyPreparedStatement statement = new MyPreparedStatement(this, sql);
        open.add(statement);
        return statement;
    }

    @Override
    public Statement createStatement(int resultSetType, int resultSetConcurrency)
            throws SQLException {
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(resultSetType, resultSetConcurrency), createStatement());
    }

    @Override
    public Statement createStatement(int resultSetType, int resultSetConcurrency,
                                     int resultSetHoldability) throws SQLException {
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(resultSetType, resultSetConcurrency), createStatement());
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int resultSetType,
                                              int resultSetConcurrency) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.MYSQL);
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(resultSetType, resultSetConcurrency),
                prepareStatement(sql));
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int resultSetType,
                                              int resultSetConcurrency, int resultSetHoldability)
            throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.MYSQL);
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(resultSetType, resultSetConcurrency),
                prepareStatement(sql));
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int autoGeneratedKeys)
            throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.MYSQL);
        // MySQL sends the key along in the OK packet anyway; there is
        // nothing to request here.
        return prepareStatement(sql);
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int[] columnIndexes)
            throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.MYSQL);
        return prepareStatement(sql);
    }

    @Override
    public PreparedStatement prepareStatement(String sql, String[] columnNames)
            throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.MYSQL);
        return prepareStatement(sql);
    }

    @Override
    public CallableStatement prepareCall(String sql) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.MYSQL);
        checkOpen();
        if (!CallSyntax.isCall(sql)) {
            // A plain query through prepareCall - Liquibase asks for its
            // schema this way. See QueryAsCallable.
            return new space.seclume.internal.jdbc.QueryAsCallable(prepareStatement(sql));
        }
        MyCallableStatement statement =
                new MyCallableStatement(this, CallSyntax.parse(sql));
        open.add(statement);
        return statement;
    }

    @Override
    public CallableStatement prepareCall(String sql, int a, int b) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.MYSQL);
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(a, b),
                prepareCall(sql));
    }

    @Override
    public CallableStatement prepareCall(String sql, int a, int b, int c) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.MYSQL);
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(a, b),
                prepareCall(sql));
    }

    /**
     * The statement, set to the result set type asked for - checked before
     * the statement was made, so a refused type leaves nothing open.
     */
    private static <T extends Statement> T typed(int type, T statement) {
        Statement target = statement instanceof space.seclume.internal.jdbc.QueryAsCallable call
                ? call.query() : statement;
        ((MyStatement) target).resultSetType(type);
        return statement;
    }

    // ---- transactions ----------------------------------------------------

    @Override
    public boolean getAutoCommit() throws SQLException {
        checkOpen();
        return autoCommit;
    }

    /**
     * The mode, without asking whether the connection is still open.
     *
     * <p>For the one caller that needs it after the connection has broken:
     * deciding whether a lost answer means a lost commit. There
     * {@code getAutoCommit()} would throw instead of answering.
     */
    boolean autoCommitNow() {
        return autoCommit;
    }

    @Override
    public void setAutoCommit(boolean value) throws SQLException {
        checkOpen();
        if (value == autoCommit) {
            return;
        }
        if (value) {
            // Whatever the block still holds belongs to the open transaction.
            session.flushPipeline();
        }
        if (value && session.inTransaction()) {
            // JDBC says switching auto-commit on commits, and it has to happen
            // here rather than ride along with the next statement - because
            // there may not be one. Deferred, a transaction followed by
            // setAutoCommit(true) and close() was rolled back by the server
            // when the connection went away: the work reported as committed
            // was lost, with no exception anywhere. Measured, not supposed -
            // see CommitOutcomeTest. The other three drivers already sent it.
            try {
                session.execute("commit");
            } catch (SQLException failure) {
                throw space.seclume.TransactionResolutionUnknownException.duringCommit(failure);
            }
        }
        // Announced, not sent: it rides along with the next statement instead
        // of costing a round trip of its own. With nothing open there is
        // nothing for it to commit, so deferring it can lose nothing.
        session.runLater("autocommit", value ? "1" : "0");
        autoCommit = value;
    }

    @Override
    public void commit() throws SQLException {
        checkOpen();
        requireManualCommit("commit");
        // Whatever the block still holds belongs to this transaction.
        session.flushPipeline();
        if (session.hasPending()) {
            // The switch to manual mode never went out, so nothing was run in
            // a transaction and there is nothing to commit. Sending one anyway
            // would be a round trip for nothing.
            return;
        }
        try {
            // A failure from here on is after COMMIT began to go out, and a
            // lost connection then means nobody knows whether it applied -
            // see TransactionResolutionUnknownException.
            session.execute("commit");
        } catch (SQLException failure) {
            throw space.seclume.TransactionResolutionUnknownException.duringCommit(failure);
        }
    }

    @Override
    public void rollback() throws SQLException {
        checkOpen();
        requireManualCommit("rollback");
        // Sent, so that a failure in the block is seen before it is discarded.
        session.flushPipeline();
        if (session.hasPending()) {
            return;
        }
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
            case TRANSACTION_READ_UNCOMMITTED -> "read uncommitted";
            case TRANSACTION_READ_COMMITTED -> "read committed";
            case TRANSACTION_REPEATABLE_READ -> "repeatable read";
            case TRANSACTION_SERIALIZABLE -> "serializable";
            default -> throw new SQLException("unknown transaction isolation level: " + level);
        };
        session.runLater("session transaction_isolation",
                "'" + name.toUpperCase(java.util.Locale.ROOT).replace(' ', '-') + "'");
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
            session.runLater("session transaction_read_only", value ? "1" : "0");
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
        requireManualCommit("set a savepoint");
        String safe = requirePlainName(name);
        session.execute("savepoint " + safe);
        return new NamedSavepoint(safe);
    }

    @Override
    public void rollback(Savepoint savepoint) throws SQLException {
        checkOpen();
        session.execute("rollback to savepoint " + requirePlainName(savepoint.getSavepointName()));
    }

    @Override
    public void releaseSavepoint(Savepoint savepoint) throws SQLException {
        checkOpen();
        session.execute("release savepoint " + requirePlainName(savepoint.getSavepointName()));
    }

    /** A savepoint name goes into the SQL text; it has to be an identifier. */
    private static String requirePlainName(String name) throws SQLException {
        if (name == null || !name.matches("[A-Za-z_][A-Za-z0-9_$]*")) {
            throw new SQLException("not a plain savepoint name: " + name);
        }
        return name;
    }

    /** With MySQL a savepoint is just a name. */
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
        return new MyDatabaseMetaData(this);
    }

    /** MySQL calls the database the "catalog" - there is no schema below it. */
    @Override
    public String getCatalog() throws SQLException {
        try (Statement statement = createStatement();
             ResultSet result = statement.executeQuery("select database()")) {
            return result.next() ? result.getString(1) : null;
        }
    }

    @Override
    public void setCatalog(String catalog) throws SQLException {
        checkOpen();
        if (catalog == null || !catalog.matches("[A-Za-z0-9_$]+")) {
            throw new SQLException("not a plain database name: " + catalog);
        }
        session.execute("use `" + catalog + "`");
    }

    @Override
    public String getSchema() {
        // In MySQL catalog and schema are the same thing; JDBC still wants
        // an answer here, and null is the right one.
        return null;
    }

    @Override
    public void setSchema(String schema) throws SQLException {
        // MySQL has no schemas below the database - setCatalog switches that -
        // and JDBC says a driver without schemas silently ignores this, which
        // is what Connector/J does.
        checkOpen();
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
    public boolean isValid(int timeout) throws SQLException {
        // JDBC: a negative timeout is a SQLException, not a value to ignore.
        // It is the one argument check on this method, and it is worth having
        // because a caller that passes -1 means something by it - usually a
        // timeout it computed and got wrong - and silently treating it as "no
        // limit" hides that.
        if (timeout < 0) {
            throw new SQLException("a validation timeout cannot be negative: " + timeout,
                    "22023");
        }
        if (closed || !session.isOpen()) {
            return false;
        }
        try {
            session.ping();
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
            for (MyStatement statement : List.copyOf(open)) {
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
        return space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.MYSQL);
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
        // A fresh, mutable one: JDBC's own example puts a mapping into it and
        // hands it back, and it is setTypeMap that says why that cannot work -
        // not an UnsupportedOperationException from an immutable map.
        return new java.util.HashMap<>();
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
        checkOpen();
        if (milliseconds < 0) {
            throw new SQLException("a network timeout cannot be negative: " + milliseconds,
                    "22023");
        }
        // The executor is not needed: the watch that closes a connection
        // waiting too long is one thread for all of them - see
        // space.seclume.internal.NetworkTimeouts.
        try {
            session().transport().networkTimeout(milliseconds);
        } catch (java.io.IOException unsupported) {
            throw new SQLFeatureNotSupportedException(unsupported.getMessage());
        }
        networkTimeout = milliseconds;
    }

    /** What {@link #setNetworkTimeout} set; 0 waits for ever. */
    private int networkTimeout;

    @Override
    public int getNetworkTimeout() throws SQLException {
        checkOpen();
        return networkTimeout;
    }

    /**
     * Resets the session without logging in again - session variables,
     * temporary tables, prepared statements. Exactly what a pool needs when a
     * connection comes back.
     */
    public void reset() throws SQLException {
        checkOpen();
        session.resetConnection();
        sessionState.clear();
        autoCommit = true;
        readOnly = false;
    }

    @Override
    public Clob createClob() throws SQLException {
        // An empty one to write into and bind; the LOB is a value on this
        // server, and setBlob/setClob send it as one.
        checkOpen();
        return space.seclume.internal.jdbc.WritableLobs.text();
    }

    @Override
    public Blob createBlob() throws SQLException {
        // An empty one to write into and bind; the LOB is a value on this
        // server, and setBlob/setClob send it as one.
        checkOpen();
        return space.seclume.internal.jdbc.WritableLobs.binary();
    }

    @Override
    public NClob createNClob() throws SQLException {
        // An empty one to write into and bind; the LOB is a value on this
        // server, and setBlob/setClob send it as one.
        checkOpen();
        return space.seclume.internal.jdbc.WritableLobs.text();
    }

    @Override
    public SQLXML createSQLXML() throws SQLException {
        checkOpen();
        return space.seclume.internal.jdbc.XmlValue.writable();
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
     * <p>Refused in auto-commit: each statement would commit on its own, and a
     * failure in the middle would leave the ones before it standing.
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

    /**
     * How this connection proved who it was - see {@link Secured}.
     *
     * <p>Delegated rather than computed: the session is the only thing that
     * watched the login happen.
     */
    @Override
    public String authenticationMethod() {
        return session.authenticationMethod();
    }

    @Override
    public java.security.cert.X509Certificate serverCertificate() {
        return session.serverCertificate();
    }

    /** What is carrying this connection, or {@code null} in the clear. */
    @Override
    public String tlsDescription() {
        return session.tlsDescription();
    }


    // ---- the flight recorder, see space.seclume.Flight -------------------

    @Override
    public java.util.List<space.seclume.Flight.Message> recent() {
        return session.recentMessages();
    }

    @Override
    public long messages() {
        return session.recordedMessages();
    }


    MyConnection rewriteBatchedInserts(boolean on) {
        this.rewriteBatchedInserts = on;
        return this;
    }

    boolean rewriteBatchedInserts() {
        return rewriteBatchedInserts;
    }
}
