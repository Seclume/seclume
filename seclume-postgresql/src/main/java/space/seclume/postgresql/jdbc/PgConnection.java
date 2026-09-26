package space.seclume.postgresql.jdbc;

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
public final class PgConnection
        implements Connection, space.seclume.internal.jdbc.Fronted, RoundTrips, Pipelined, Secured, space.seclume.Flight,
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
        for (PgStatement statement : new java.util.ArrayList<>(open)) {
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
                "select current_setting('max_connections')::int - current_setting('superuser_reserved_connections')::int",
                "select count(*) from pg_stat_activity where backend_type = 'client backend'");
    }


    /** The server's idle limit - PostgreSQL 14 and later: {@code idle_session_timeout}, in milliseconds. */
    @Override
    public java.time.Duration idleLimit() throws SQLException {
        checkOpen();
        return space.seclume.internal.jdbc.Capacities.idleLimit(this,
                "select setting::bigint from pg_settings where name = 'idle_session_timeout'",
                java.time.Duration.ofMillis(1));
    }

    /** See {@link space.seclume.SessionContext}: {@code set_config}, with the next statement. */
    @Override
    public void setSessionContext(String name, String value) throws SQLException {
        checkOpen();
        space.seclume.internal.jdbc.ContextValues.check(name, value);
        if (transactionPooler) {
            throw new java.sql.SQLFeatureNotSupportedException("behind a transaction pooler "
                    + "(proxyMode=transaction) a session value would reach the next client "
                    + "of the same server connection - set it inside the transaction with "
                    + "set_config(name, value, true) instead");
        }
        String sql = "select set_config('" + name + "', "
                + space.seclume.internal.jdbc.ContextValues.dollarQuoted(value) + ", false)";
        sessionState.note(sql);
        session.runLater(sql);
    }

    /**
     * {@code COPY ... FROM STDIN}, fed from {@code data}: the bulk import path,
     * far faster than any batch of inserts.
     *
     * <pre>
     *   PgConnection pg = connection.unwrap(PgConnection.class);
     *   long rows = pg.copyIn("copy orders (id, total) from stdin (format csv)", csvStream);
     * </pre>
     *
     * The stream is read to its end and not closed; its bytes are sent as they
     * are, in the statement's format (text, csv or binary) and the session's
     * encoding, UTF-8.
     *
     * @return the rows copied
     */
    public long copyIn(String sql, java.io.InputStream data) throws SQLException {
        checkOpen();
        return session.copyIn(sql, data);
    }

    /**
     * {@code COPY ... TO STDOUT}, into {@code sink}: the export path. The
     * stream is written and not closed.
     *
     * @return the rows copied
     */
    public long copyOut(String sql, java.io.OutputStream sink) throws SQLException {
        checkOpen();
        return session.copyOut(sql, sink);
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
     * Everything a session can carry that is not the transaction, in one
     * round trip: open cursors, a changed role, every setting ({@code RESET
     * ALL} goes back to what the login gave), listened channels, session-level
     * advisory locks, temporary tables and sequences' cached values. Prepared
     * statements stay - the driver's own and the pool's cache use them, and
     * they carry no state of a borrower's. The isolation and read-only the
     * connection has are sent again when they are not the login's.
     */
    @Override
    public boolean resetSessionState() throws SQLException {
        checkOpen();
        if (!sessionState.changed()) {
            return true;
        }
        if (!autoCommit) {
            return false;                        // DISCARD TEMP refuses inside a transaction
        }
        session.dropPendingContext();
        session.execute("close all; set session authorization default; reset all; "
                + "unlisten *; select pg_advisory_unlock_all(); discard temp; "
                + "discard sequences");
        sessionState.clear();
        if (isolation != TRANSACTION_READ_COMMITTED) {
            int wanted = isolation;
            isolation = TRANSACTION_READ_COMMITTED;
            setTransactionIsolation(wanted);
        }
        if (readOnly) {
            readOnly = false;
            setReadOnly(true);
        }
        return true;
    }

    private final PgSession session;
    private final String url;
    private final List<PgStatement> open = new ArrayList<>();
    private final AtomicLong statementCounter = new AtomicLong();

    /** A name for a plan nobody has parsed yet. */
    String newStatementName() {
        return "seclume_" + statementCounter.incrementAndGet();
    }

    private boolean autoCommit = true;
    private int savepointCounter;
    private boolean readOnly;
    private boolean closed;
    private int isolation = TRANSACTION_READ_COMMITTED;

    PgConnection(PgSession session, String url) {
        this(session, url, SeclumeUrl.DEFAULT_STATEMENT_CACHE);
    }

    /**
     * A JDBC connection on a session this process did not open.
     *
     * <p>The companion to {@link PgSession#resume}: that one picks the stream
     * up, this one puts the JDBC surface on it, so an application - Spring
     * Data, Hibernate, anything holding a {@link Connection} - works on it
     * without knowing where it came from.
     *
     * <p><b>{@code inTransaction} is a fact the driver cannot establish, and
     * that is why it is an argument.</b> A stream handed over may be sitting
     * inside an open transaction, and the JDBC surface has no way to ask: the
     * server states its transaction status in every {@code ReadyForQuery}, but
     * the next one arrives only after a statement has run, and by then this
     * connection would already have behaved as though it knew. Saying
     * {@code true} sets auto-commit off <b>without</b> announcing a
     * {@code BEGIN}, because the transaction is already open and a second
     * begin would be a warning and a lie. Saying {@code false} leaves
     * auto-commit on, which is what JDBC promises a fresh connection.
     *
     * <p>Whoever hands the stream over knows which it is; nobody else does.
     */
    public static Connection resume(PgSession session, boolean inTransaction) {
        return resume(session, new space.seclume.internal.jdbc.ConnectionFacts(!inTransaction,
                false, TRANSACTION_READ_COMMITTED, 0, 0));
    }

    /**
     * The same, with everything the giving connection knew about itself - see
     * {@link space.seclume.internal.jdbc.ConnectionFacts}. The counters carry
     * on where they stopped, so no statement or savepoint is named after one
     * the server still holds.
     */
    public static Connection resume(PgSession session,
            space.seclume.internal.jdbc.ConnectionFacts facts) {
        PgConnection connection = new PgConnection(session, "jdbc:seclume:postgresql:resumed");
        connection.autoCommit = facts.autoCommit();
        connection.readOnly = facts.readOnly();
        connection.isolation = facts.isolation();
        connection.statementCounter.set(facts.statements());
        connection.savepointCounter = facts.savepoints();
        return connection;
    }

    /**
     * What this connection knows about itself, for whoever takes its session
     * over - read it <b>before</b> the session is detached.
     */
    public space.seclume.internal.jdbc.ConnectionFacts facts() {
        return new space.seclume.internal.jdbc.ConnectionFacts(autoCommit, readOnly, isolation,
                statementCounter.get(), savepointCounter);
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
        if (statementCacheSize == 0) {
            return null;
        }
        Idle plan = idlePlans.remove(sql);
        // Recorded by fingerprint, like everything else: a cache report that
        // listed the statements by their text would carry every value in
        // them, which is precisely the report nobody could then share.
        space.seclume.jfr.Observed.statementCache(sql,
                space.seclume.QueryFingerprint.Dialect.POSTGRESQL, plan != null);
        return plan;
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
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.POSTGRESQL);
        checkOpen();
        Idle idle = takePlan(sql);
        PgPreparedStatement statement = idle == null
                ? new PgPreparedStatement(this, sql,
                        newStatementName(), null)
                : new PgPreparedStatement(this, sql, idle.name(), idle.described());
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
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.POSTGRESQL);
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(resultSetType, resultSetConcurrency),
                prepareStatement(sql));
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int resultSetType,
                                              int resultSetConcurrency, int resultSetHoldability)
            throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.POSTGRESQL);
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(resultSetType, resultSetConcurrency),
                prepareStatement(sql));
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int autoGeneratedKeys)
            throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.POSTGRESQL);
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
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.POSTGRESQL);
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
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.POSTGRESQL);
        throw new SQLFeatureNotSupportedException(
                "generated keys by column number are not supported - name the columns "
                + "instead: prepareStatement(sql, new String[] {\"id\"})");
    }


    @Override
    public CallableStatement prepareCall(String sql) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.POSTGRESQL);
        checkOpen();
        if (!CallSyntax.isCall(sql)) {
            // A plain query through prepareCall - Liquibase asks for its
            // schema this way. See QueryAsCallable.
            return new space.seclume.internal.jdbc.QueryAsCallable(prepareStatement(sql));
        }
        CallSyntax call = CallSyntax.parse(sql);
        // The plan cache is keyed by the statement that goes to the server,
        // not by what the caller wrote - two callers writing the same call
        // with and without braces share one plan, which is right.
        String statement = PgCallableStatement.statementFor(call);
        Idle idle = takePlan(statement);
        PgCallableStatement prepared = idle == null
                ? new PgCallableStatement(this, call,
                        newStatementName(), null)
                : new PgCallableStatement(this, call, idle.name(), idle.described());
        open.add(prepared);
        return prepared;
    }

    @Override
    public CallableStatement prepareCall(String sql, int a, int b) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.POSTGRESQL);
        return typed(space.seclume.internal.jdbc.ResultSetTypes.require(a, b),
                prepareCall(sql));
    }

    @Override
    public CallableStatement prepareCall(String sql, int a, int b, int c) throws SQLException {
        sql = space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.POSTGRESQL);
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
        ((PgStatement) target).resultSetType(type);
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
        try {
            // A failure from here on is after COMMIT began to go out, and a
            // lost connection then means nobody knows whether it applied -
            // see TransactionResolutionUnknownException.
            session.execute("commit");
        } catch (SQLException failure) {
            throw space.seclume.TransactionResolutionUnknownException.duringCommit(failure);
        }
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
        isolation = level;
        if (transactionPooler) {
            session.setBeginStatement(beginStatement());
            return;
        }
        // Rides along with the next statement - see PgSession.runLater.
        session.runLater("set session characteristics as transaction isolation level " + name);
    }

    /**
     * Whether a transaction pooler sits in front ({@code proxyMode=transaction}).
     *
     * <p>Then the server session belongs to this client for one transaction
     * only, and whatever is set on it stays for whoever gets it next. Measured
     * behind PgBouncer: a {@code setReadOnly(true)} on one connection made the
     * next client's session read-only, and an isolation level did the same.
     * So in this mode the two are never set on the session; they travel in the
     * transaction's own {@code BEGIN}, which the driver sends with the first
     * statement anyway. In auto-commit mode they are hints, as JDBC allows -
     * there is no transaction of one's own to carry them. A session context
     * is refused for the same reason.
     */
    private boolean transactionPooler;

    void transactionPooler(boolean on) {
        this.transactionPooler = on;
    }

    /** {@code BEGIN} with this connection's isolation and read-only, for a transaction pooler. */
    private String beginStatement() {
        StringBuilder begin = new StringBuilder("BEGIN"); // seclume-allow: statement text, no values in it
        switch (isolation) {
            case TRANSACTION_REPEATABLE_READ -> begin.append(" ISOLATION LEVEL REPEATABLE READ");
            case TRANSACTION_SERIALIZABLE -> begin.append(" ISOLATION LEVEL SERIALIZABLE");
            default -> { }
        }
        if (readOnly) {
            begin.append(" READ ONLY");
        }
        return begin.toString();
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
            readOnly = value;
            if (transactionPooler) {
                session.setBeginStatement(beginStatement());
                return;
            }
            session.runLater("set session characteristics as transaction "
                    + (value ? "read only" : "read write"));
        }
    }

    @Override
    public Savepoint setSavepoint() throws SQLException {
        return setSavepoint("zl_" + (++savepointCounter));
    }

    /**
     * A savepoint, and with it Spring's {@code Propagation.NESTED}.
     *
     * <p>Sent with {@code execute}, which carries a waiting {@code BEGIN} in
     * front of it: a savepoint taken as the first thing in a transaction has
     * to land inside that transaction, not before it, where PostgreSQL would
     * answer with a warning and nothing to roll back to.
     */
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
        requireManualCommit("roll back to a savepoint");
        // What is queued was sent after the savepoint; it is being undone,
        // and after a failed statement the server would refuse it anyway.
        session.discardPending();
        session.execute("rollback to savepoint "
                + requirePlainName(savepoint.getSavepointName()));
    }

    @Override
    public void releaseSavepoint(Savepoint savepoint) throws SQLException {
        checkOpen();
        requireManualCommit("release a savepoint");
        session.execute("release savepoint " + requirePlainName(savepoint.getSavepointName()));
    }

    /** A savepoint name goes into the SQL text; it has to be an identifier. */
    private static String requirePlainName(String name) throws SQLException {
        if (name == null || !name.matches("[A-Za-z_][A-Za-z0-9_$]*")) {
            throw new SQLException("not a plain savepoint name: " + name);
        }
        return name;
    }

    /** A savepoint is a name to PostgreSQL. */
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
        // PostgreSQL cannot switch the database of a connection. The one it is
        // on is fine - a pool puts back what it read, HikariCP's catalog
        // setting does exactly that - and any other is refused: pgjdbc
        // ignores it, and a caller then runs its statements in a database it
        // did not ask for without a word.
        if (catalog == null || catalog.equals(session.database())) {
            return;
        }
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
        return space.seclume.internal.jdbc.JdbcEscapes.translate(sql,
                space.seclume.internal.jdbc.JdbcEscapes.Dialect.POSTGRESQL);
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

    @Override
    public Clob createClob() throws SQLException {
        throw large("CLOB");
    }

    /**
     * Refused on purpose. JDBC's {@code createBlob} promises an empty
     * writable value with no side effect, and PostgreSQL has no such thing: a
     * large object is created in the database and stays there whether or not
     * anybody ever stores its oid. Creating one is therefore asked for by
     * name - see {@link PgLargeObjects} - so that what it leaves behind is the
     * caller's decision rather than a factory method's.
     */
    @Override
    public Blob createBlob() throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "PostgreSQL has no free-standing empty BLOB - create a large object with "
                + "connection.unwrap(PgLargeObjects.class).create(bytes), or use a bytea "
                + "column and setBytes");
    }

    @Override
    public NClob createNClob() throws SQLException {
        throw large("NCLOB");
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
        // Large objects are asked for by name rather than being reachable
        // through createBlob - PgLargeObjects says why.
        if (iface == PgLargeObjects.class) {
            checkOpen();
            return iface.cast(new PgLargeObjects(this));
        }
        if (iface.isInstance(session)) {
            return iface.cast(session);
        }
        throw new SQLException("not a wrapper for " + iface.getName());
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) {
        return iface.isInstance(this) || iface.isInstance(session)
                || iface == PgLargeObjects.class;
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

    /**
     * The notifications this connection's {@code LISTEN}s brought, oldest
     * first: what has arrived with earlier answers, and - when nothing has -
     * whatever the server holds for it, asked for with one round trip that
     * changes nothing else.
     *
     * <pre>
     *   PgConnection pg = connection.unwrap(PgConnection.class);
     *   pg.createStatement().execute("listen orders");
     *   for (PgNotification n : pg.notifications(Duration.ofSeconds(30))) { ... }
     * </pre>
     */
    public java.util.List<space.seclume.postgresql.PgNotification> notifications()
            throws SQLException {
        checkOpen();
        return session.takeNotifications(true);
    }

    /**
     * The same, waiting up to {@code wait} for the first one - asking every
     * fifty milliseconds, which on a virtual thread costs a sleep and a
     * round trip, not a platform thread. An empty list when none came.
     */
    public java.util.List<space.seclume.postgresql.PgNotification> notifications(
            java.time.Duration wait) throws SQLException {
        long until = System.nanoTime() + wait.toNanos();
        while (true) {
            java.util.List<space.seclume.postgresql.PgNotification> arrived = notifications();
            long left = until - System.nanoTime();
            if (!arrived.isEmpty() || left <= 0) {
                return arrived;
            }
            try {
                Thread.sleep(Math.min(50, Math.max(1, left / 1_000_000)));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return java.util.List.of();
            }
        }
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
