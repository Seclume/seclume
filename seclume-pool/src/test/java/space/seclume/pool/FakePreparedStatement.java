package space.seclume.pool;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A prepared statement with the settings a borrower can change, for the
 * statement cache.
 *
 * <p>{@link StubDataSource}'s statements refuse every getter, so the cache
 * never learns their defaults and keeps none of them: through the stub the
 * cache's whole keep-and-restore path is never run. This one answers like a
 * driver: the getters read what the setters wrote, and each method can be
 * told to fail.
 */
final class FakePreparedStatement {

    final PreparedStatement proxy;
    volatile int maxRows;
    volatile int queryTimeout;
    volatile int fetchSize;
    volatile int maxFieldSize;
    volatile int fetchDirection = ResultSet.FETCH_FORWARD;
    volatile boolean closeOnCompletion;
    volatile boolean closed;
    final AtomicInteger closes = new AtomicInteger();
    final AtomicInteger clearParameters = new AtomicInteger();
    final AtomicInteger clearWarnings = new AtomicInteger();
    final AtomicInteger clearBatch = new AtomicInteger();
    /** Setter calls, by name - a restore sets only what differs. */
    final List<String> setters = new CopyOnWriteArrayList<>();
    /** Methods that throw from now on - a driver whose statement broke. */
    final Set<String> failing = ConcurrentHashMap.newKeySet();
    /** Methods that throw unchecked from now on. */
    final Set<String> failingUnchecked = ConcurrentHashMap.newKeySet();

    FakePreparedStatement() {
        this.proxy = (PreparedStatement) Proxy.newProxyInstance(
                FakePreparedStatement.class.getClassLoader(), new Class<?>[] {PreparedStatement.class},
                (self, method, args) -> {
                    String name = method.getName();
                    if (failing.contains(name)) {
                        throw new SQLException(name + " failed");
                    }
                    if (failingUnchecked.contains(name)) {
                        throw new IllegalStateException(name + " failed");
                    }
                    if (name.startsWith("set")) {
                        setters.add(name);
                    }
                    return switch (name) {
                        case "getMaxRows" -> maxRows;
                        case "setMaxRows" -> {
                            maxRows = (int) args[0];
                            yield null;
                        }
                        case "getQueryTimeout" -> queryTimeout;
                        case "setQueryTimeout" -> {
                            queryTimeout = (int) args[0];
                            yield null;
                        }
                        case "getFetchSize" -> fetchSize;
                        case "setFetchSize" -> {
                            fetchSize = (int) args[0];
                            yield null;
                        }
                        case "getMaxFieldSize" -> maxFieldSize;
                        case "setMaxFieldSize" -> {
                            maxFieldSize = (int) args[0];
                            yield null;
                        }
                        case "getFetchDirection" -> fetchDirection;
                        case "setFetchDirection" -> {
                            fetchDirection = (int) args[0];
                            yield null;
                        }
                        case "isCloseOnCompletion" -> closeOnCompletion;
                        case "closeOnCompletion" -> {
                            closeOnCompletion = true;
                            yield null;
                        }
                        case "clearParameters" -> {
                            clearParameters.incrementAndGet();
                            yield null;
                        }
                        case "clearWarnings" -> {
                            clearWarnings.incrementAndGet();
                            yield null;
                        }
                        case "clearBatch" -> {
                            clearBatch.incrementAndGet();
                            yield null;
                        }
                        case "close" -> {
                            closes.incrementAndGet();
                            closed = true;
                            yield null;
                        }
                        case "isClosed" -> closed;
                        case "hashCode" -> System.identityHashCode(self);
                        case "equals" -> self == args[0];
                        case "toString" -> "FakePreparedStatement";
                        default -> throw new SQLException("the fake statement does not implement " + name);
                    };
                });
    }

    /** A connection whose every prepareStatement hands out this one statement. */
    Connection connection() {
        Preparing preparing = new Preparing();
        preparing.next = this;
        return preparing.connection;
    }

    /** A connection that prepares a new fake statement for each call, and keeps them. */
    static final class Preparing {
        final List<FakePreparedStatement> prepared = new CopyOnWriteArrayList<>();
        final List<String> texts = new CopyOnWriteArrayList<>();
        /** Handed out by the next prepare instead of a new one. */
        FakePreparedStatement next;
        /** Applied to each new statement before it is handed out: a driver's defaults. */
        java.util.function.Consumer<FakePreparedStatement> defaults = statement -> { };
        final Connection connection = (Connection) Proxy.newProxyInstance(
                FakePreparedStatement.class.getClassLoader(), new Class<?>[] {Connection.class},
                (self, method, args) -> switch (method.getName()) {
                    case "prepareStatement" -> {
                        FakePreparedStatement statement = next != null ? next : new FakePreparedStatement();
                        next = null;
                        defaults.accept(statement);
                        prepared.add(statement);
                        texts.add((String) args[0]);
                        yield statement.proxy;
                    }
                    case "hashCode" -> System.identityHashCode(self);
                    case "equals" -> self == args[0];
                    case "toString" -> "Preparing";
                    default -> throw new SQLException("not used: " + method.getName());
                });
    }
}
