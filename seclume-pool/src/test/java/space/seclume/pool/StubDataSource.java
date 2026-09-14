package space.seclume.pool;

import java.io.PrintWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import javax.sql.DataSource;

/**
 * A {@code DataSource} that hands out countable connections without a database
 * having to run.
 *
 * <p>The mechanics of a pool - size, reuse, timeout, returning,
 * replacing broken ones - does not depend on the database. Checking it here
 * makes the tests fast and, which weighs more, independent of whether a server
 * happens to run on the machine. The test against the real server then checks
 * that the assumptions hold there too.
 */
final class StubDataSource implements DataSource {

    /** A connection that records what happens to it. */
    static final class StubConnection {

        final Connection proxy;
        final AtomicBoolean closed = new AtomicBoolean();
        final AtomicInteger rollbacks = new AtomicInteger();
        volatile boolean autoCommit = true;
        volatile boolean readOnly;
        volatile int isolation = Connection.TRANSACTION_READ_COMMITTED;
        volatile boolean valid = true;
        final AtomicInteger validations = new AtomicInteger();
        /** From now on every call fails the way a dropped socket fails. */
        volatile boolean broken;
        volatile String catalog;
        volatile String schema;
        final AtomicInteger statements = new AtomicInteger();
        final List<StubStatement> statementsHandedOut = new CopyOnWriteArrayList<>();

        StubConnection() {
            this.proxy = (Connection) Proxy.newProxyInstance(
                    Connection.class.getClassLoader(), new Class<?>[] {Connection.class},
                    new Handler(this));
        }
    }

    /** The little of a statement that these tests need: is it still open. */
    static final class StubStatement {

        final java.sql.Statement proxy;
        final AtomicBoolean closed = new AtomicBoolean();

        StubStatement() {
            this.proxy = (java.sql.Statement) Proxy.newProxyInstance(
                    StubStatement.class.getClassLoader(),
                    new Class<?>[] {java.sql.PreparedStatement.class},
                    (self, method, args) -> switch (method.getName()) {
                        case "close" -> {
                            closed.set(true);
                            yield null;
                        }
                        case "isClosed" -> closed.get();
                        case "toString" -> "StubStatement";
                        case "hashCode" -> System.identityHashCode(self);
                        case "equals" -> self == args[0];
                        default -> throw new SQLException(
                                "the stub statement does not implement " + method.getName());
                    });
        }
    }

    /** Answers exactly the calls the pool really makes. */
    private record Handler(StubConnection state) implements InvocationHandler {

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws SQLException {
            // A connection that has broken answers nothing any more - that is
            // what a dropped socket looks like from up here.
            if (state.broken && !method.getName().equals("close")
                    && !method.getName().equals("isClosed")) {
                throw new SQLException("the connection to the server was lost", "08006");
            }
            return switch (method.getName()) {
                case "createStatement", "prepareStatement", "prepareCall" -> {
                    state.statements.incrementAndGet();
                    StubStatement statement = new StubStatement();
                    state.statementsHandedOut.add(statement);
                    yield statement.proxy;
                }
                case "setSavepoint" -> (java.sql.Savepoint) Proxy.newProxyInstance(
                        StubDataSource.class.getClassLoader(),
                        new Class<?>[] {java.sql.Savepoint.class},
                        (self, m, a) -> switch (m.getName()) {
                            case "getSavepointName" -> args.length > 0 ? args[0] : "unnamed";
                            case "getSavepointId" -> 1;
                            case "toString" -> "StubSavepoint";
                            case "hashCode" -> System.identityHashCode(self);
                            case "equals" -> self == a[0];
                            default -> throw new SQLException(
                                    "the stub savepoint does not implement " + m.getName());
                        });
                case "setCatalog" -> {
                    state.catalog = (String) args[0];
                    yield null;
                }
                case "getCatalog" -> state.catalog;
                case "setSchema" -> {
                    state.schema = (String) args[0];
                    yield null;
                }
                case "getSchema" -> state.schema;
                case "close" -> {
                    state.closed.set(true);
                    yield null;
                }
                case "isClosed" -> state.closed.get();
                case "isValid" -> {
                    state.validations.incrementAndGet();
                    yield state.valid && !state.closed.get();
                }
                case "getAutoCommit" -> state.autoCommit;
                case "setAutoCommit" -> {
                    state.autoCommit = (boolean) args[0];
                    yield null;
                }
                case "isReadOnly" -> state.readOnly;
                case "setReadOnly" -> {
                    state.readOnly = (boolean) args[0];
                    yield null;
                }
                case "getTransactionIsolation" -> state.isolation;
                case "setTransactionIsolation" -> {
                    state.isolation = (int) args[0];
                    yield null;
                }
                case "rollback" -> {
                    state.rollbacks.incrementAndGet();
                    yield null;
                }
                case "abort" -> {
                    state.closed.set(true);
                    yield null;
                }
                case "commit", "clearWarnings" -> null;
                case "getWarnings" -> null;
                case "toString" -> "StubConnection";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> throw new SQLException(
                        "the stub does not implement " + method.getName());
            };
        }
    }

    private final List<StubConnection> handedOut = new CopyOnWriteArrayList<>();
    private final AtomicInteger opened = new AtomicInteger();
    private volatile SQLException failure;
    private volatile long delayMillis;

    /** From now on every connect fails - like a dead database. */
    void failWith(SQLException failure) {
        this.failure = failure;
    }

    void succeedAgain() {
        this.failure = null;
    }

    void delayEachConnect(long millis) {
        this.delayMillis = millis;
    }

    int openedCount() {
        return opened.get();
    }

    List<StubConnection> handedOut() {
        return handedOut;
    }

    @Override
    public Connection getConnection() throws SQLException {
        if (failure != null) {
            throw failure;
        }
        if (delayMillis > 0) {
            try {
                Thread.sleep(delayMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        opened.incrementAndGet();
        StubConnection connection = new StubConnection();
        handedOut.add(connection);
        return connection.proxy;
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        throw new SQLException("not used in these tests");
    }

    @Override
    public PrintWriter getLogWriter() {
        return null;
    }

    @Override
    public void setLogWriter(PrintWriter out) {
        // not used
    }

    @Override
    public void setLoginTimeout(int seconds) {
        // not used
    }

    @Override
    public int getLoginTimeout() {
        return 0;
    }

    @Override
    public Logger getParentLogger() {
        return Logger.getGlobal();
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        throw new SQLException("not a wrapper");
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) {
        return false;
    }
}
