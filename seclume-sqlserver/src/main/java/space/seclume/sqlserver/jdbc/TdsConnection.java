package space.seclume.sqlserver.jdbc;

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
public final class TdsConnection implements Connection, space.seclume.internal.jdbc.Fronted, RoundTrips, Pipelined, Secured, space.seclume.Flight,
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
        for (TdsStatement statement : new java.util.ArrayList<>(open)) {
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
                "select count(*) from sys.dm_exec_sessions where is_user_process = 1");
    }


    /** SQL Server closes no idle session - see {@link space.seclume.ServerIdleLimit}. */
    @Override
    public java.time.Duration idleLimit() throws SQLException {
        checkOpen();
        return null;
    }

    /** See {@link space.seclume.SessionContext}: {@code sp_set_session_context}. */
    @Override
    public void setSessionContext(String name, String value) throws SQLException {
        checkOpen();
        space.seclume.internal.jdbc.ContextValues.check(name, value);
        String sql = "exec sp_set_session_context "
                + space.seclume.internal.jdbc.ContextValues.nString(name) + ", "
                + space.seclume.internal.jdbc.ContextValues.nString(value);
        sessionState.note(sql);
        session.contextLater(sql);
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
     * The RESETCONNECTION bit on the next request - {@code sp_reset_connection}
     * without a round trip of its own: temporary tables, SET options, session
     * context and the application role go back to what the login gave. The
     * isolation and read-only the connection has are sent again, riding the
     * same request, when they are not the login's.
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
        session.dropPendingContext();
        session.resetBeforeNextRequest();
        sessionState.clear();
        if (isolation != TRANSACTION_READ_COMMITTED) {
            int wanted = isolation;
            isolation = TRANSACTION_READ_COMMITTED;
            setTransactionIsolation(wanted);
        }
        return true;
    }

    private final TdsSession session;
    private final String url;
    private final List<TdsStatement> open = new ArrayList<>();
    private boolean autoCommit = true;
    private boolean readOnly;
    private boolean closed;
    private int isolation = TRANSACTION_READ_COMMITTED;
    private int savepointCounter;

    /**
     * A JDBC connection on a session this process did not open - what an
     * application holds, put back on a session that was handed over.
     *
     * <p>{@code facts} are what the giving connection knew about itself (see
     * {@link space.seclume.internal.jdbc.ConnectionFacts}); the server session
     * carries everything else.
     */
    public static java.sql.Connection resume(TdsSession session,
            space.seclume.internal.jdbc.ConnectionFacts facts) {
        TdsConnection connection = new TdsConnection(session, "jdbc:seclume:sqlserver:resumed");
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

    /**
     * Loads rows into {@code table} with SQL Server's bulk load - the path
     * {@code bcp} and SSIS use, far faster than inserts.
     *
     * <pre>
     *   TdsConnection sql = connection.unwrap(TdsConnection.class);
     *   long loaded = sql.bulkInsert("dbo.orders", new String[] {"id", "total"}, rows);
     * </pre>
     *
     * <p>Each column's type is taken from its first non-null value among the
     * first thousand rows, as a parameter's type is taken from its value; a
     * later row that does not fit is refused before any of it is sent, and the
     * load is cancelled. Unlike {@code bcp}'s default, check constraints and
     * foreign keys are checked and triggers fire: a bulk load here means what an
     * insert would, only faster.
     *
     * @param table   the target table, as it would stand in an insert
     * @param columns the target columns, in the order of each row's values
     * @param rows    the rows, read once - a stream is fine
     * @return the rows loaded
     */
    public long bulkInsert(String table, String[] columns, Iterable<Object[]> rows)
            throws SQLException {
        checkOpen();
        java.util.Iterator<Object[]> source = rows.iterator();
        java.util.List<Object[]> sample = new java.util.ArrayList<>();
        while (sample.size() < 1000 && source.hasNext()) {
            sample.add(source.next());
        }
        // Which target columns take NULL - a NOT NULL one is described with the
        // fixed-length type; see TdsBulk.Column.
        StringBuilder probe = new StringBuilder("select top 0 "); // seclume-allow: statement text, no values in it
        for (int i = 0; i < columns.length; i++) {
            probe.append(i > 0 ? ", " : "").append('[').append(columns[i].replace("]", "]]"))
                    .append(']');
        }
        java.util.List<space.seclume.sqlserver.tds.TdsColumn> target =
                session.sqlBatch(probe.append(" from ").append(table).toString(), null).columns();
        boolean[] nullable = new boolean[columns.length];
        for (int i = 0; i < columns.length; i++) {
            nullable[i] = i >= target.size() || target.get(i).nullable();
        }
        java.util.List<space.seclume.sqlserver.tds.TdsBulk.Column> described =
                space.seclume.sqlserver.tds.TdsBulk.columns(columns, sample, nullable);
        StringBuilder statement = new StringBuilder("insert bulk ").append(table).append(" ("); // seclume-allow: statement text, no values in it
        for (int i = 0; i < described.size(); i++) {
            if (i > 0) {
                statement.append(", ");
            }
            statement.append(described.get(i).declaration());
        }
        statement.append(") with (CHECK_CONSTRAINTS, FIRE_TRIGGERS)");
        java.util.Iterator<Object[]> all = new java.util.Iterator<>() {
            private int sampled;

            @Override
            public boolean hasNext() {
                return sampled < sample.size() || source.hasNext();
            }

            @Override
            public Object[] next() {
                return sampled < sample.size() ? sample.get(sampled++) : source.next();
            }
        };
        return session.bulkLoad(statement.toString(), described, all);
    }

    /** Whether ASCII text may go as varchar - see VarcharParameters. */
    private boolean varcharParameters = true;

    void varcharParameters(boolean on) {
        this.varcharParameters = on;
    }

    boolean varcharParameters() {
        return varcharParameters;
    }

    /** Which server and database a statement text means something in - see VarcharParameters. */
    String serverKey() throws SQLException {
        int options = url.indexOf('?');
        return (options < 0 ? url : url.substring(0, options)) + "|" + session().database();
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
     * 63 - see the performance notes.
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
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.SQLSERVER);
        checkOpen();
        TdsPreparedStatement statement = new TdsPreparedStatement(this, sql);
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
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.SQLSERVER);
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(resultSetType, resultSetConcurrency),
                prepareStatement(sql));
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int resultSetType,
                                              int resultSetConcurrency, int resultSetHoldability)
            throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.SQLSERVER);
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(resultSetType, resultSetConcurrency),
                prepareStatement(sql));
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int autoGeneratedKeys)
            throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.SQLSERVER);
        return prepareStatement(sql, autoGeneratedKeys == Statement.RETURN_GENERATED_KEYS);
    }

    /**
     * Which columns the keys come from is not passed on, and cannot be: the
     * key arrives from {@code scope_identity()}, which knows only the one
     * identity column a table may have. Asking for a different column would
     * have to be refused rather than silently answered with that one - but no
     * caller does, and Hibernate uses this overload simply to say "the
     * identity, please".
     */
    @Override
    public PreparedStatement prepareStatement(String sql, int[] columnIndexes)
            throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.SQLSERVER);
        return prepareStatement(sql, true);
    }

    @Override
    public PreparedStatement prepareStatement(String sql, String[] columnNames)
            throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.SQLSERVER);
        return prepareStatement(sql, true);
    }

    private PreparedStatement prepareStatement(String sql, boolean generatedKeys)
            throws SQLException {
        checkOpen();
        TdsPreparedStatement statement = new TdsPreparedStatement(this, sql, generatedKeys);
        open.add(statement);
        return statement;
    }

    @Override
    public CallableStatement prepareCall(String sql) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.SQLSERVER);
        checkOpen();
        if (!CallSyntax.isCall(sql)) {
            // A plain query through prepareCall - Liquibase asks for its
            // schema this way. See QueryAsCallable.
            return new space.seclume.internal.jdbc.QueryAsCallable(prepareStatement(sql));
        }
        TdsCallableStatement statement =
                new TdsCallableStatement(this, CallSyntax.parse(sql));
        open.add(statement);
        return statement;
    }

    @Override
    public CallableStatement prepareCall(String sql, int a, int b) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.SQLSERVER);
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(a, b),
                prepareCall(sql));
    }

    @Override
    public CallableStatement prepareCall(String sql, int a, int b, int c) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.SQLSERVER);
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
        ((TdsStatement) target).resultSetType(type);
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
            try {
                session.execute("commit tran");
            } catch (SQLException failure) {
                throw space.seclume.TransactionResolutionUnknownException.duringCommit(failure);
            }
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
        try {
            // A failure from here on is after COMMIT began to go out, and a
            // lost connection then means nobody knows whether it applied -
            // see TransactionResolutionUnknownException.
            session.execute("if @@trancount > 0 commit tran");
        } catch (SQLException failure) {
            throw space.seclume.TransactionResolutionUnknownException.duringCommit(failure);
        }
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
        // The schema the session already has is fine - a pool puts back what
        // it read. Another one cannot be had, and saying so beats mssql-jdbc's
        // silence, after which the statements run in the user's schema anyway.
        if (schema == null || schema.equals(getSchema())) {
            return;
        }
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
        return space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.SQLSERVER);
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
     * From here on, an update nobody is waiting for is buffered.
     *
     * <p>{@link space.seclume.Pipeline} exists so that an application can
     * write a unit of work once and have it cost one round trip where the
     * protocol allows it. TDS allows it: several RPCs travel in one message,
     * separated by {@code 0xff}, which is how {@code executeBatch} has always
     * sent its rows. The block points the same machinery at many statements
     * instead of many values.
     *
     * <p><b>What is not buffered</b>, because it cannot be: a query, a
     * statement that asks for generated keys, and the first execution of a
     * statement the server has not compiled yet - that one has to come back
     * with a handle before anything can quote it. Each of those sends what is
     * gathered first, so the order on the server is the order in the block.
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

}
