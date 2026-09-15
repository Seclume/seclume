package space.seclume.pool;

import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.NClob;
import java.sql.PreparedStatement;
import java.sql.SQLClientInfoException;
import java.sql.SQLException;
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

/**
 * The connection the application holds in its hand.
 *
 * <p>It passes everything through to the real connection, with one difference:
 * {@link #close()} closes nothing but gives back. That is the whole point of a
 * pool - application code writes
 * {@code try (Connection c = dataSource.getConnection())} and does not have to
 * know whether a pool sits behind it.
 *
 * <p>Before it goes back, things are tidied up: an open transaction is rolled
 * back, and settings the application changed return to their starting values.
 * Without that the next application inherits an {@code autoCommit=false} or a
 * {@code readOnly} it never set - and the failure then shows up somewhere else
 * entirely.
 *
 * <p>If something goes wrong while tidying up, the connection is not
 * put back but closed. A connection in an unknown state
 * is worse than a missing one.
 */
final class PooledConnection implements Connection {

    private final SeclumePool pool;
    private final PoolEntry entry;
    /** Not final: a broken connection is replaced underneath the application. */
    private Connection delegate;
    /** Statements this connection keeps between borrows, or {@code null}. */
    private final StatementCache statements;

    private final boolean initialAutoCommit;
    private final boolean initialReadOnly;
    private final int initialIsolation;

    private boolean touchedAutoCommit;
    private boolean touchedReadOnly;
    private boolean touchedIsolation;
    private boolean closed;
    private boolean broken;

    // What a rebuild has to put back, and what forbids one. All of it is
    // written on the calling thread and read on the calling thread: a borrowed
    // connection belongs to one thread at a time.
    private boolean autoCommitOn;
    private boolean readOnly;
    private int isolation;
    private String catalog;
    private String schema;
    private boolean touchedCatalog;
    private boolean touchedSchema;
    /** Work done since the last commit, rollback or autocommit change. */
    private boolean workSinceBoundary;
    /** A savepoint stands - then there is a transaction with a shape to it. */
    private boolean savepointStanding;
    /**
     * Statements handed out during this borrow; a rebuild needs them closed.
     *
     * <p><b>Null until the first one.</b> It used to be allocated eagerly, and
     * an {@code ArrayList} with room for four is some 64 bytes - paid by every
     * borrow, including the many that never create a statement at all. That was
     * the whole difference to HikariCP in allocation: 120 bytes per
     * borrow-and-return against 56. Measured with the GC profiler, which says
     * it to the byte while the timing at this scale says nothing.
     */
    private List<Statement> handedOut;
    /** Somebody creates statements without end - then we stop counting and stop rebuilding. */
    private boolean tooManyStatements;
    /** One rebuild per borrow: twice in a row is a server saying no. */
    private boolean renewedOnce;
    /** Whether anything at all was asked of the connection while it was out. */
    private boolean used;

    /**
     * The state to restore comes from the entry, which read it when the
     * connection was opened - asking the driver here would put a round trip
     * into every handout.
     */
    PooledConnection(SeclumePool pool, PoolEntry entry, StatementCache statements) {
        this.pool = pool;
        this.entry = entry;
        this.statements = statements;
        this.delegate = entry.connection();
        this.initialAutoCommit = entry.initialAutoCommit();
        this.initialReadOnly = entry.initialReadOnly();
        this.initialIsolation = entry.initialIsolation();
        this.autoCommitOn = initialAutoCommit;
        this.readOnly = initialReadOnly;
        this.isolation = initialIsolation;
    }

    // ---- Zurueckgeben ----------------------------------------------------

    @Override
    public void close() {
        if (closed) {
            return;      // JDBC requires a second close() to do nothing
        }
        closed = true;
        if (!broken) {
            try {
                restore();
            } catch (SQLException e) {
                broken = true;
            }
        }
        pool.release(entry, broken);
    }

    /** Returns the connection to the state it was handed out in. */
    private void restore() throws SQLException {
        // Only when a transaction can actually be open: with autoCommit on
        // there is nothing to roll back, and asking the driver costs more than
        // the flag this class already knows.
        if (touchedAutoCommit ? !delegate.getAutoCommit() : !initialAutoCommit) {
            // What was not committed was not intended.
            delegate.rollback();
        }
        if (touchedAutoCommit && delegate.getAutoCommit() != initialAutoCommit) {
            delegate.setAutoCommit(initialAutoCommit);
        }
        if (touchedReadOnly && delegate.isReadOnly() != initialReadOnly) {
            delegate.setReadOnly(initialReadOnly);
        }
        if (touchedIsolation && delegate.getTransactionIsolation() != initialIsolation) {
            delegate.setTransactionIsolation(initialIsolation);
        }
        // Only when something was actually asked of the connection: if
        // nothing was, nothing can have warned. The call looks free and is
        // not - on several drivers it is a synchronized method, and it sits on
        // the path of every single return.
        if (used) {
            delegate.clearWarnings();
        }
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    private void checkOpen() throws SQLException {
        if (closed) {
            throw new SQLException(
                    "this connection was already returned to the pool", "08003");
        }
    }

    /**
     * Runs a call, and where it is honest, survives the connection breaking.
     *
     * <p>The SQLState class {@code 08} means "connection". A syntax error says
     * nothing about the connection; throwing it away for that would be waste.
     *
     * <p>A broken connection used to end here: marked, handed on, retired on
     * return. It still does whenever the application could notice the
     * difference. But in the common case it cannot: nothing is open, nothing is
     * half-done, and the call that failed is one the connection itself answers.
     * Then a new connection is opened - the secret source is asked again, which
     * is the whole reason this is possible without keeping a password anywhere -
     * the session settings are put back, and the call is repeated once. The
     * application saw a connection from a pool, and it still has one.
     *
     * <p>Repeated <b>once</b>. A second failure straight after is a server that
     * is gone, not a socket that was dropped, and retrying into that would turn
     * one error into a wait.
     */
    private <T> T call(SqlCall<T> action) throws SQLException {
        checkOpen();
        used = true;
        try {
            return record(action.run(delegate));
        } catch (SQLException e) {
            if (!isConnectionFailure(e)) {
                throw e;
            }
            if (!canRenew()) {
                broken = true;
                throw e;
            }
            try {
                renew();
            } catch (SQLException cannot) {
                // No new connection either - then the first failure is the one
                // worth telling, with this one attached to it.
                broken = true;
                e.addSuppressed(cannot);
                throw e;
            }
            try {
                return record(action.run(delegate));
            } catch (SQLException again) {
                broken = true;
                again.addSuppressed(e);
                throw again;
            }
        }
    }

    private static boolean isConnectionFailure(SQLException e) {
        return e.getSQLState() != null && e.getSQLState().startsWith("08");
    }

    /**
     * Whether the application could tell the difference.
     *
     * <p>Every one of these says the same thing in a different way: is there
     * something on this connection whose outcome nobody can establish any
     * more? An open transaction, a statement still in the application's hand, a
     * savepoint - each of them would have to be silently dropped, and silently
     * dropping work is how a booking happens twice.
     */
    private boolean canRenew() {
        if (renewedOnce || tooManyStatements || savepointStanding || workSinceBoundary) {
            return false;
        }
        if (!pool.settings().isRenewBrokenConnections()) {
            return false;
        }
        if (handedOut != null) {
            for (Statement statement : handedOut) {
                try {
                    if (!statement.isClosed()) {
                        return false;
                    }
                } catch (SQLException e) {
                    // Cannot even be asked - then it counts as open.
                    return false;
                }
            }
        }
        return true;
    }

    /** A new connection, set up the way this one was. */
    private void renew() throws SQLException {
        pool.renew(entry);
        delegate = entry.connection();
        renewedOnce = true;
        if (handedOut != null) {
            handedOut.clear();
        }
        if (autoCommitOn != initialAutoCommit) {
            delegate.setAutoCommit(autoCommitOn);
        }
        if (readOnly != initialReadOnly) {
            delegate.setReadOnly(readOnly);
        }
        if (isolation != initialIsolation) {
            delegate.setTransactionIsolation(isolation);
        }
        // Catalog and schema only when they were set here: asking a fresh
        // connection to go where it already is costs a round trip for nothing.
        if (touchedCatalog) {
            delegate.setCatalog(catalog);
        }
        if (touchedSchema) {
            delegate.setSchema(schema);
        }
    }

    /**
     * Notes what came out, because a rebuild depends on it.
     *
     * <p>Centrally rather than in each of the ten methods that hand out a
     * statement - one of them would be forgotten, and forgetting one here means
     * rebuilding under an open statement.
     */
    private <T> T record(T result) {
        if (result instanceof Statement statement) {
            if (!autoCommitOn) {
                // Inside a transaction a statement is work, whether or not it
                // is still open by the time anything breaks.
                workSinceBoundary = true;
            }
            if (handedOut == null) {
                handedOut = new ArrayList<>(4);
            }
            if (handedOut.size() >= 64) {
                tooManyStatements = true;
            } else {
                handedOut.add(statement);
            }
        } else if (result instanceof Savepoint) {
            savepointStanding = true;
        }
        return result;
    }

    private void run(SqlAction action) throws SQLException {
        call(c -> {
            action.run(c);
            return null;
        });
    }

    @FunctionalInterface
    private interface SqlCall<T> {
        T run(Connection connection) throws SQLException;
    }

    @FunctionalInterface
    private interface SqlAction {
        void run(Connection connection) throws SQLException;
    }

    // ---- everything else passes through ----------------------------------

    @Override
    public Statement createStatement() throws SQLException {
        return call(Connection::createStatement);
    }

    @Override
    public PreparedStatement prepareStatement(String sql) throws SQLException {
        // Only this plain form is cached. The variants that ask for generated
        // keys or a scrollable result set mean something different every time,
        // and a cache that returns "close enough" is worse than none.
        if (statements == null) {
            return call(c -> c.prepareStatement(sql));
        }
        return call(c -> CachedPreparedStatement.wrap(statements, sql,
                statements.take(c, sql)));
    }

    @Override
    public CallableStatement prepareCall(String sql) throws SQLException {
        return call(c -> c.prepareCall(sql));
    }

    @Override
    public Statement createStatement(int type, int concurrency) throws SQLException {
        return call(c -> c.createStatement(type, concurrency));
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int type, int concurrency)
            throws SQLException {
        return call(c -> c.prepareStatement(sql, type, concurrency));
    }

    @Override
    public CallableStatement prepareCall(String sql, int type, int concurrency)
            throws SQLException {
        return call(c -> c.prepareCall(sql, type, concurrency));
    }

    @Override
    public Statement createStatement(int type, int concurrency, int holdability)
            throws SQLException {
        return call(c -> c.createStatement(type, concurrency, holdability));
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int type, int concurrency,
                                              int holdability) throws SQLException {
        return call(c -> c.prepareStatement(sql, type, concurrency, holdability));
    }

    @Override
    public CallableStatement prepareCall(String sql, int type, int concurrency, int holdability)
            throws SQLException {
        return call(c -> c.prepareCall(sql, type, concurrency, holdability));
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int autoGeneratedKeys)
            throws SQLException {
        return call(c -> c.prepareStatement(sql, autoGeneratedKeys));
    }

    @Override
    public PreparedStatement prepareStatement(String sql, int[] columnIndexes)
            throws SQLException {
        return call(c -> c.prepareStatement(sql, columnIndexes));
    }

    @Override
    public PreparedStatement prepareStatement(String sql, String[] columnNames)
            throws SQLException {
        return call(c -> c.prepareStatement(sql, columnNames));
    }

    @Override
    public String nativeSQL(String sql) throws SQLException {
        return call(c -> c.nativeSQL(sql));
    }

    @Override
    public void setAutoCommit(boolean autoCommit) throws SQLException {
        touchedAutoCommit = true;
        run(c -> c.setAutoCommit(autoCommit));
        // Either direction ends whatever was open: switching it on commits on
        // every server we speak to, switching it off starts from nothing.
        autoCommitOn = autoCommit;
        workSinceBoundary = false;
        savepointStanding = false;
    }

    @Override
    public boolean getAutoCommit() throws SQLException {
        return call(Connection::getAutoCommit);
    }

    @Override
    public void commit() throws SQLException {
        run(Connection::commit);
        workSinceBoundary = false;
        savepointStanding = false;
    }

    @Override
    public void rollback() throws SQLException {
        run(Connection::rollback);
        workSinceBoundary = false;
        savepointStanding = false;
    }

    @Override
    public DatabaseMetaData getMetaData() throws SQLException {
        return call(Connection::getMetaData);
    }

    @Override
    public void setReadOnly(boolean readOnly) throws SQLException {
        touchedReadOnly = true;
        run(c -> c.setReadOnly(readOnly));
        this.readOnly = readOnly;
    }

    @Override
    public boolean isReadOnly() throws SQLException {
        return call(Connection::isReadOnly);
    }

    @Override
    public void setCatalog(String catalog) throws SQLException {
        run(c -> c.setCatalog(catalog));
        this.catalog = catalog;
        this.touchedCatalog = true;
    }

    @Override
    public String getCatalog() throws SQLException {
        return call(Connection::getCatalog);
    }

    @Override
    public void setTransactionIsolation(int level) throws SQLException {
        touchedIsolation = true;
        run(c -> c.setTransactionIsolation(level));
        this.isolation = level;
    }

    @Override
    public int getTransactionIsolation() throws SQLException {
        return call(Connection::getTransactionIsolation);
    }

    @Override
    public SQLWarning getWarnings() throws SQLException {
        return call(Connection::getWarnings);
    }

    @Override
    public void clearWarnings() throws SQLException {
        run(Connection::clearWarnings);
    }

    @Override
    public Map<String, Class<?>> getTypeMap() throws SQLException {
        return call(Connection::getTypeMap);
    }

    @Override
    public void setTypeMap(Map<String, Class<?>> map) throws SQLException {
        run(c -> c.setTypeMap(map));
    }

    @Override
    public void setHoldability(int holdability) throws SQLException {
        run(c -> c.setHoldability(holdability));
    }

    @Override
    public int getHoldability() throws SQLException {
        return call(Connection::getHoldability);
    }

    @Override
    public Savepoint setSavepoint() throws SQLException {
        return call(Connection::setSavepoint);
    }

    @Override
    public Savepoint setSavepoint(String name) throws SQLException {
        return call(c -> c.setSavepoint(name));
    }

    @Override
    public void rollback(Savepoint savepoint) throws SQLException {
        run(c -> c.rollback(savepoint));
        // Still inside a transaction, and still nothing a new connection could
        // carry over - the savepoint belonged to the session that is gone.
    }

    @Override
    public void releaseSavepoint(Savepoint savepoint) throws SQLException {
        run(c -> c.releaseSavepoint(savepoint));
    }

    @Override
    public Clob createClob() throws SQLException {
        return call(Connection::createClob);
    }

    @Override
    public Blob createBlob() throws SQLException {
        return call(Connection::createBlob);
    }

    @Override
    public NClob createNClob() throws SQLException {
        return call(Connection::createNClob);
    }

    @Override
    public SQLXML createSQLXML() throws SQLException {
        return call(Connection::createSQLXML);
    }

    @Override
    public boolean isValid(int timeout) throws SQLException {
        return !closed && delegate.isValid(timeout);
    }

    @Override
    public void setClientInfo(String name, String value) throws SQLClientInfoException {
        delegate.setClientInfo(name, value);
    }

    @Override
    public void setClientInfo(Properties properties) throws SQLClientInfoException {
        delegate.setClientInfo(properties);
    }

    @Override
    public String getClientInfo(String name) throws SQLException {
        return call(c -> c.getClientInfo(name));
    }

    @Override
    public Properties getClientInfo() throws SQLException {
        return call(Connection::getClientInfo);
    }

    @Override
    public Array createArrayOf(String typeName, Object[] elements) throws SQLException {
        return call(c -> c.createArrayOf(typeName, elements));
    }

    @Override
    public Struct createStruct(String typeName, Object[] attributes) throws SQLException {
        return call(c -> c.createStruct(typeName, attributes));
    }

    @Override
    public void setSchema(String schema) throws SQLException {
        run(c -> c.setSchema(schema));
        this.schema = schema;
        this.touchedSchema = true;
    }

    @Override
    public String getSchema() throws SQLException {
        return call(Connection::getSchema);
    }

    /**
     * {@code abort} means: end this connection right now. It does not go back
     * into the pool - a caller who aborts has a reason.
     */
    @Override
    public void abort(Executor executor) throws SQLException {
        broken = true;
        delegate.abort(executor);
        close();
    }

    @Override
    public void setNetworkTimeout(Executor executor, int milliseconds) throws SQLException {
        run(c -> c.setNetworkTimeout(executor, milliseconds));
    }

    @Override
    public int getNetworkTimeout() throws SQLException {
        return call(Connection::getNetworkTimeout);
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) {
            return iface.cast(this);
        }
        return delegate.unwrap(iface);
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) throws SQLException {
        return iface.isInstance(this) || delegate.isWrapperFor(iface);
    }

    /**
     * The real connection behind it - for tests.
     *
     * <p>Not via {@code unwrap(Connection.class)}: per JDBC that returns this
     * very object, because it is a {@code Connection} itself.
     */
    Connection delegate() {
        return delegate;
    }

    @Override
    public String toString() {
        return "PooledConnection[" + (closed ? "returned" : "in use") + "]";
    }
}
