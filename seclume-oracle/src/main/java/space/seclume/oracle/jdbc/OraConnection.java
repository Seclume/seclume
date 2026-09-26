package space.seclume.oracle.jdbc;

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
public final class OraConnection implements Connection, space.seclume.internal.jdbc.Fronted, RoundTrips, Pipelined, Secured, space.seclume.Flight,
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
        for (OraStatement statement : new java.util.ArrayList<>(open)) {
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
                "select to_number(value) from v$parameter where name = 'sessions'",
                "select count(*) from v$session where type = 'USER'");
    }


    /**
     * The server's idle limit - the profile's {@code IDLE_TIME}, in minutes,
     * as {@code user_resource_limits} shows it to the user itself.
     */
    @Override
    public java.time.Duration idleLimit() throws SQLException {
        checkOpen();
        return space.seclume.internal.jdbc.Capacities.idleLimit(this,
                "select case when \"LIMIT\" in ('UNLIMITED', 'DEFAULT') then null else to_number(\"LIMIT\") end from user_resource_limits where resource_name = 'IDLE_TIME'",
                java.time.Duration.ofMinutes(1));
    }

    /**
     * See {@link space.seclume.SessionContext}: only {@code client_identifier}.
     * Any other application context lives in a namespace a DBA creates and
     * only its own package may set - nothing a driver can do on its behalf.
     */
    @Override
    public void setSessionContext(String name, String value) throws SQLException {
        checkOpen();
        space.seclume.internal.jdbc.ContextValues.check(name, value);
        if (!name.equalsIgnoreCase("client_identifier")) {
            throw new java.sql.SQLFeatureNotSupportedException("Oracle keeps an application "
                    + "context in a namespace a DBA creates, set only by its own package - "
                    + "call that package; the one context a session may set itself is "
                    + "client_identifier (SYS_CONTEXT('USERENV', 'CLIENT_IDENTIFIER'))");
        }
        try (java.sql.PreparedStatement statement = prepareStatement(
                "begin dbms_session.set_identifier(?); end;")) {
            statement.setString(1, value);
            statement.execute();
        }
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
     * Package state, the client identifier, module, action and client info,
     * back to empty - one round trip. An {@code ALTER SESSION} cannot be
     * undone without knowing what it replaced: that connection is reported as
     * not reset, and a pool closes it rather than lend it again.
     */
    @Override
    public boolean resetSessionState() throws SQLException {
        checkOpen();
        if (!sessionState.changed()) {
            return true;
        }
        if (sessionState.irreversible() || !autoCommit) {
            return false;
        }
        session.query("begin dbms_session.modify_package_state(dbms_session.reinitialize); "
                + "dbms_session.clear_identifier; dbms_application_info.set_module(null, null); "
                + "dbms_application_info.set_client_info(null); end;", null);
        sessionState.clear();
        return true;
    }

    private final OracleSession session;
    private final String url;
    private final List<OraStatement> open = new ArrayList<>();
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
    public static java.sql.Connection resume(OracleSession session,
            space.seclume.internal.jdbc.ConnectionFacts facts) {
        // The session keeps its own flag - it is a bit in every execute call -
        // and the two have to agree, or statements are committed by the
        // server that the connection believes are in a transaction.
        session.setAutoCommit(facts.autoCommit());
        session.setReadOnlyTransactions(facts.readOnly());
        OraConnection connection = new OraConnection(session, "jdbc:seclume:oracle:resumed");
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
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.ORACLE);
        checkOpen();
        OraPreparedStatement statement = new OraPreparedStatement(this, sql);
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
    public PreparedStatement prepareStatement(String sql, int a, int b) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.ORACLE);
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(a, b),
                prepareStatement(sql));
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int a, int b, int c)
            throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.ORACLE);
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(a, b),
                prepareStatement(sql));
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int autoGeneratedKeys)
            throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.ORACLE);
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
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.ORACLE);
        checkOpen();
        OraPreparedStatement statement = (OraPreparedStatement) prepareStatement(sql);
        statement.wantGeneratedKeys(columnNames);
        return statement;
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int[] columnIndexes)
            throws SQLException {
        // Refused rather than ignored: this used to hand back a plain
        // statement, and getGeneratedKeys then had nothing - an insert that
        // asked for its key and silently got none. Oracle's clause names
        // columns, and a number would first have to be looked up in the
        // dictionary for a table the statement names, quoted or not.
        throw new SQLFeatureNotSupportedException(
                "generated keys by column number are not supported - name the columns "
                + "instead: prepareStatement(sql, new String[] {\"id\"})");
    }

    @Override
    public CallableStatement prepareCall(String sql) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.ORACLE);
        checkOpen();
        if (!CallSyntax.isCall(sql)) {
            // A plain query through prepareCall - Liquibase asks for its
            // schema this way. See QueryAsCallable.
            return new space.seclume.internal.jdbc.QueryAsCallable(prepareStatement(sql));
        }
        OraCallableStatement statement =
                new OraCallableStatement(this, CallSyntax.parse(sql));
        open.add(statement);
        return statement;
    }

    @Override
    public CallableStatement prepareCall(String sql, int a, int b) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.ORACLE);
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(a, b),
                prepareCall(sql));
    }

    @Override
    public CallableStatement prepareCall(String sql, int a, int b, int c) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.ORACLE);
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
        ((OraStatement) target).resultSetType(type);
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
            try {
                session.commit();
            } catch (SQLException failure) {
                throw space.seclume.TransactionResolutionUnknownException.duringCommit(failure);
            }
        }
        autoCommit = value;
        session.setAutoCommit(value);
    }

    @Override
    public void commit() throws SQLException {
        checkOpen();
        requireManualCommit("commit");
        try {
            // A failure from here on is after COMMIT began to go out, and a
            // lost connection then means nobody knows whether it applied -
            // see TransactionResolutionUnknownException.
            session.commit();
        } catch (SQLException failure) {
            throw space.seclume.TransactionResolutionUnknownException.duringCommit(failure);
        }
    }

    @Override
    public void rollback() throws SQLException {
        checkOpen();
        requireManualCommit("roll back");
        session.rollback();
    }

    /**
     * The three transaction calls JDBC forbids while auto-commit is on.
     *
     * <p>PostgreSQL's driver refused these from the start and this one did
     * not, which is the kind of difference that only shows up when the same
     * application is pointed at both. And the refusal is not pedantry: code
     * that calls {@code commit()} on an auto-commit connection believes it is
     * ending a transaction that was never open, and the writes it thought it
     * was grouping were each committed on their own as they went.
     */
    private void requireManualCommit(String what) throws SQLException {
        if (autoCommit) {
            throw new SQLException("cannot " + what
                    + " while auto-commit is on - call setAutoCommit(false) first",
                    "25000");
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
            case TRANSACTION_SERIALIZABLE -> "serializable";
            default -> throw new SQLException(
                    "Oracle knows only READ COMMITTED and SERIALIZABLE, not level " + level);
        };
        // For the session, not the transaction: SET TRANSACTION ISOLATION
        // LEVEL held for one transaction only, and Spring sets the level
        // while auto-commit is still on - so it was committed away with
        // itself and never governed anything. ALTER SESSION stays.
        session.query("alter session set isolation_level = "
                + name.replace(' ', '_'), null);
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
            // Not sent now: Oracle's read-only lasts one transaction and has
            // to open it. The session sends it in front of each one - see
            // OracleSession.setReadOnlyTransactions.
            session.setReadOnlyTransactions(value);
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
        // Oracle has no catalogs, and for that case JDBC says what to do:
        // "if the driver does not support catalogs, it will silently ignore
        // this request". getCatalog answers null, as it always did.
        checkOpen();
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
        return space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.ORACLE);
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
        session.query("rollback", null);
        autoCommit = true;
        session.setAutoCommit(true);
        readOnly = false;
        session.setReadOnlyTransactions(false);
        // The level is a session setting now, so it has to be taken back
        // explicitly - or the next borrower runs serializable unasked.
        setTransactionIsolation(TRANSACTION_READ_COMMITTED);
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
        return space.seclume.internal.jdbc.WritableLobs.text();
    }

    @Override
    public Blob createBlob() {
        return space.seclume.internal.jdbc.WritableLobs.binary();
    }

    @Override
    public NClob createNClob() {
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
