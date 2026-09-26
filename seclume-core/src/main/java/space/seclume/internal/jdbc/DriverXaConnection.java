package space.seclume.internal.jdbc;

import java.sql.Array;
import java.sql.SQLClientInfoException;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.NClob;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Savepoint;
import java.sql.ShardingKey;
import java.sql.Statement;
import java.sql.Struct;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.sql.ConnectionEvent;
import javax.sql.ConnectionEventListener;
import javax.sql.StatementEventListener;
import javax.sql.XAConnection;
import javax.transaction.xa.XAResource;

/**
 * A connection for a transaction manager - the same for all four drivers.
 *
 * <p>This is the shape a JTA container expects: it hands out the
 * {@link Connection} the application works with and the {@link XAResource} the
 * transaction manager drives, and both refer to the same session - which is
 * what makes two-phase commit possible at all.
 *
 * <p>Closing the handed-out {@code Connection} does <b>not</b> end the
 * session: the container keeps this object and asks for a new handle. That is
 * the contract, and it is why the handle's {@code close()} only tells the
 * listeners.
 *
 * <p>The handle is written out rather than proxied - see {@code Handle}. It was
 * a proxy until 22.09.2026, changed on the assumption that a native image
 * needs such a thing registered; measuring said otherwise, and the change was
 * kept for the better reason: a concrete class that implements
 * {@code Connection} does not compile with a method missing, so the risk the
 * proxy was hiding from is now the compiler's to catch.
 */
public final class DriverXaConnection implements XAConnection {

    private final Connection session;
    private final XAResource resource;
    private final AutoCloseable extra;
    private final List<ConnectionEventListener> listeners = new CopyOnWriteArrayList<>();
    private Handle handle;
    private boolean closed;

    /**
     * @param session  the driver's own connection - never handed out directly
     * @param resource the branch control built on that same session
     */
    public DriverXaConnection(Connection session, XAResource resource) {
        this(session, resource, null);
    }

    /**
     * @param extra something else that belongs to this XA connection and has
     *              to go with it - SQL Server needs a second connection for
     *              the transaction commands, and it must not outlive this one
     */
    public DriverXaConnection(Connection session, XAResource resource, AutoCloseable extra) {
        this.session = session;
        this.resource = resource;
        this.extra = extra;
    }

    @Override
    public XAResource getXAResource() {
        return resource;
    }

    @Override
    public Connection getConnection() throws SQLException {
        if (closed) {
            throw new SQLException("this XA connection is closed", "08003");
        }
        if (handle != null) {
            handle.detached = true;
        }
        handle = new Handle();
        if (session instanceof Fronted fronted) {
            fronted.front(handle);                // statements name the handle - see Fronted
        }
        return handle;
    }

    @Override
    public void close() throws SQLException {
        if (!closed) {
            closed = true;
            try {
                session.close();
            } finally {
                closeExtra();
            }
        }
    }

    private void closeExtra() throws SQLException {
        if (extra == null) {
            return;
        }
        try {
            extra.close();
        } catch (SQLException e) {
            throw e;
        } catch (Exception e) {
            throw new SQLException("the second connection of this XA connection did not close", e);
        }
    }

    @Override
    public void addConnectionEventListener(ConnectionEventListener listener) {
        listeners.add(listener);
    }

    @Override
    public void removeConnectionEventListener(ConnectionEventListener listener) {
        listeners.remove(listener);
    }

    @Override
    public void addStatementEventListener(StatementEventListener listener) {
        // Statement pooling is the container's business and these drivers do
        // not do it, so these listeners would never hear anything.
    }

    @Override
    public void removeStatementEventListener(StatementEventListener listener) {
    }

    /**
     * The {@link Connection} a container hands to the application.
     *
     * <p><b>Written out rather than proxied.</b> The reason it was a proxy -
     * {@code Connection} has fifty methods and one left out would go straight
     * to the session behind the handle - is answered by the compiler instead: a
     * concrete class that says {@code implements Connection} does not build
     * with a method missing. What the compiler cannot check is that each of
     * them goes through the guard, which is why there is only one guard to
     * go through.
     *
     * <p>Two things happen around every call and neither is repeated fifty
     * times: the handle refuses once it has been given back, and a broken
     * connection - SQLState class 08, not a rejected statement - is reported
     * to the listeners before the exception goes on. See {@link #call} and
     * {@link #run}.
     */
    private final class Handle implements Connection {

        private boolean detached;

        /** What a delegating method does, so that the guard is written once. */
        @FunctionalInterface
        private interface Returning<T> {
            T on(Connection session) throws SQLException;
        }

        @FunctionalInterface
        private interface Doing {
            void on(Connection session) throws SQLException;
        }

        private <T> T call(Returning<T> body) throws SQLException {
            if (detached) {
                throw new SQLException("this connection handle was given back already", "08003");
            }
            try {
                return body.on(session);
            } catch (SQLException failure) {
                report(failure);
                throw failure;
            }
        }

        private void run(Doing body) throws SQLException {
            call(session -> {
                body.on(session);
                return null;
            });
        }

        /** A broken line, not a rejected statement - only that one is fatal. */
        private void report(SQLException failure) {
            String state = failure.getSQLState();
            if (state == null || !state.startsWith("08")) {
                return;
            }
            ConnectionEvent event = new ConnectionEvent(DriverXaConnection.this, failure);
            for (ConnectionEventListener listener : listeners) {
                listener.connectionErrorOccurred(event);
            }
        }

        /**
         * Gives the handle back. Does <b>not</b> end the session: the
         * container keeps the XA connection and asks for a new handle.
         */
        @Override
        public void close() {
            if (!detached) {
                detached = true;
                if (session instanceof Fronted fronted) {
                    fronted.front(null);
                }
                ConnectionEvent event = new ConnectionEvent(DriverXaConnection.this);
                for (ConnectionEventListener listener : listeners) {
                    listener.connectionClosed(event);
                }
            }
        }

        @Override
        public boolean isClosed() throws SQLException {
            return detached || session.isClosed();
        }

        // ---- everything else goes straight through ------------------------

        @Override
        public void abort(java.util.concurrent.Executor a0) throws SQLException {
            run(d -> d.abort(a0));
        }

        @Override
        public void clearWarnings() throws SQLException {
            run(d -> d.clearWarnings());
        }

        @Override
        public void commit() throws SQLException {
            run(d -> d.commit());
        }

        @Override
        public Array createArrayOf(String a0, Object[] a1) throws SQLException {
            return call(d -> d.createArrayOf(a0, a1));
        }

        @Override
        public Blob createBlob() throws SQLException {
            return call(d -> d.createBlob());
        }

        @Override
        public Clob createClob() throws SQLException {
            return call(d -> d.createClob());
        }

        @Override
        public NClob createNClob() throws SQLException {
            return call(d -> d.createNClob());
        }

        @Override
        public SQLXML createSQLXML() throws SQLException {
            return call(d -> d.createSQLXML());
        }

        @Override
        public Statement createStatement() throws SQLException {
            return call(d -> d.createStatement());
        }

        @Override
        public Statement createStatement(int a0, int a1, int a2) throws SQLException {
            return call(d -> d.createStatement(a0, a1, a2));
        }

        @Override
        public Statement createStatement(int a0, int a1) throws SQLException {
            return call(d -> d.createStatement(a0, a1));
        }

        @Override
        public Struct createStruct(String a0, Object[] a1) throws SQLException {
            return call(d -> d.createStruct(a0, a1));
        }

        @Override
        public boolean getAutoCommit() throws SQLException {
            return call(d -> d.getAutoCommit());
        }

        @Override
        public String getCatalog() throws SQLException {
            return call(d -> d.getCatalog());
        }

        @Override
        public Properties getClientInfo() throws SQLException {
            return call(d -> d.getClientInfo());
        }

        @Override
        public String getClientInfo(String a0) throws SQLException {
            return call(d -> d.getClientInfo(a0));
        }

        @Override
        public int getHoldability() throws SQLException {
            return call(d -> d.getHoldability());
        }

        @Override
        public DatabaseMetaData getMetaData() throws SQLException {
            return call(d -> d.getMetaData());
        }

        @Override
        public int getNetworkTimeout() throws SQLException {
            return call(d -> d.getNetworkTimeout());
        }

        @Override
        public String getSchema() throws SQLException {
            return call(d -> d.getSchema());
        }

        @Override
        public int getTransactionIsolation() throws SQLException {
            return call(d -> d.getTransactionIsolation());
        }

        @Override
        public java.util.Map<String, Class<?>> getTypeMap() throws SQLException {
            return call(d -> d.getTypeMap());
        }

        @Override
        public SQLWarning getWarnings() throws SQLException {
            return call(d -> d.getWarnings());
        }

        @Override
        public boolean isReadOnly() throws SQLException {
            return call(d -> d.isReadOnly());
        }

        @Override
        public boolean isValid(int a0) throws SQLException {
            return call(d -> d.isValid(a0));
        }

        @Override
        public boolean isWrapperFor(Class<?> a0) throws SQLException {
            return call(d -> d.isWrapperFor(a0));
        }

        @Override
        public String nativeSQL(String a0) throws SQLException {
            return call(d -> d.nativeSQL(a0));
        }

        @Override
        public CallableStatement prepareCall(String a0, int a1, int a2, int a3) throws SQLException {
            return call(d -> d.prepareCall(a0, a1, a2, a3));
        }

        @Override
        public CallableStatement prepareCall(String a0, int a1, int a2) throws SQLException {
            return call(d -> d.prepareCall(a0, a1, a2));
        }

        @Override
        public CallableStatement prepareCall(String a0) throws SQLException {
            return call(d -> d.prepareCall(a0));
        }

        @Override
        public PreparedStatement prepareStatement(String a0, int[] a1) throws SQLException {
            return call(d -> d.prepareStatement(a0, a1));
        }

        @Override
        public PreparedStatement prepareStatement(String a0, String[] a1) throws SQLException {
            return call(d -> d.prepareStatement(a0, a1));
        }

        @Override
        public PreparedStatement prepareStatement(String a0, int a1, int a2, int a3) throws SQLException {
            return call(d -> d.prepareStatement(a0, a1, a2, a3));
        }

        @Override
        public PreparedStatement prepareStatement(String a0, int a1, int a2) throws SQLException {
            return call(d -> d.prepareStatement(a0, a1, a2));
        }

        @Override
        public PreparedStatement prepareStatement(String a0, int a1) throws SQLException {
            return call(d -> d.prepareStatement(a0, a1));
        }

        @Override
        public PreparedStatement prepareStatement(String a0) throws SQLException {
            return call(d -> d.prepareStatement(a0));
        }

        @Override
        public void releaseSavepoint(Savepoint a0) throws SQLException {
            run(d -> d.releaseSavepoint(a0));
        }

        @Override
        public void rollback() throws SQLException {
            run(d -> d.rollback());
        }

        @Override
        public void rollback(Savepoint a0) throws SQLException {
            run(d -> d.rollback(a0));
        }

        @Override
        public void setAutoCommit(boolean a0) throws SQLException {
            run(d -> d.setAutoCommit(a0));
        }

        @Override
        public void setCatalog(String a0) throws SQLException {
            run(d -> d.setCatalog(a0));
        }

        /**
         * One of two methods on {@code Connection} that throw something
         * narrower than {@code SQLException}, so the guard above does not fit
         * and they carry their own.
         */
        @Override
        public void setClientInfo(String a0, String a1) throws SQLClientInfoException {
            if (detached) {
                throw new SQLClientInfoException("this connection handle was given back "
                        + "already", "08003", null);
            }
            session.setClientInfo(a0, a1);
        }

        /** The other one - see above. */
        @Override
        public void setClientInfo(Properties a0) throws SQLClientInfoException {
            if (detached) {
                throw new SQLClientInfoException("this connection handle was given back "
                        + "already", "08003", null);
            }
            session.setClientInfo(a0);
        }

        @Override
        public void setHoldability(int a0) throws SQLException {
            run(d -> d.setHoldability(a0));
        }

        @Override
        public void setNetworkTimeout(java.util.concurrent.Executor a0, int a1) throws SQLException {
            run(d -> d.setNetworkTimeout(a0, a1));
        }

        @Override
        public void setReadOnly(boolean a0) throws SQLException {
            run(d -> d.setReadOnly(a0));
        }

        @Override
        public Savepoint setSavepoint() throws SQLException {
            return call(d -> d.setSavepoint());
        }

        @Override
        public Savepoint setSavepoint(String a0) throws SQLException {
            return call(d -> d.setSavepoint(a0));
        }

        @Override
        public void setSchema(String a0) throws SQLException {
            run(d -> d.setSchema(a0));
        }

        @Override
        public void setTransactionIsolation(int a0) throws SQLException {
            run(d -> d.setTransactionIsolation(a0));
        }

        @Override
        public void setTypeMap(java.util.Map<String, Class<?>> a0) throws SQLException {
            run(d -> d.setTypeMap(a0));
        }

        @Override
        public <T> T unwrap(Class<T> a0) throws SQLException {
            return call(d -> d.unwrap(a0));
        }
    }

}
