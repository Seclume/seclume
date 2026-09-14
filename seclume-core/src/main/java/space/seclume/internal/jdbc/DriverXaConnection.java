package space.seclume.internal.jdbc;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
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
 * <p>The handle is a proxy rather than a class with sixty delegating methods.
 * There is nothing to gain from writing those out, and every one of them would
 * be a place to forget something when {@code Connection} grows.
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
        return (Connection) Proxy.newProxyInstance(
                DriverXaConnection.class.getClassLoader(),
                new Class<?>[] {Connection.class}, handle);
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

    /** The handle the application holds: the session with a different close. */
    private final class Handle implements InvocationHandler {

        private boolean detached;

        @Override
        public Object invoke(Object proxy, Method method, Object[] arguments) throws Throwable {
            String name = method.getName();
            if ("close".equals(name)) {
                if (!detached) {
                    detached = true;
                    ConnectionEvent event = new ConnectionEvent(DriverXaConnection.this);
                    for (ConnectionEventListener listener : listeners) {
                        listener.connectionClosed(event);
                    }
                }
                return null;
            }
            if ("isClosed".equals(name)) {
                return detached || session.isClosed();
            }
            if (detached) {
                throw new SQLException("this connection handle was given back already", "08003");
            }
            try {
                return method.invoke(session, arguments);
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                if (cause instanceof SQLException failure && isFatal(failure)) {
                    ConnectionEvent event = new ConnectionEvent(DriverXaConnection.this, failure);
                    for (ConnectionEventListener listener : listeners) {
                        listener.connectionErrorOccurred(event);
                    }
                }
                throw cause;
            }
        }

        /** A broken line, not a rejected statement - only that one is fatal. */
        private boolean isFatal(SQLException failure) {
            String state = failure.getSQLState();
            return state != null && state.startsWith("08");
        }
    }
}
