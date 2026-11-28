package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;

import space.seclume.ServerCapacity;

/**
 * The pool asks the first connection it opens how many sessions the server
 * allows. That question had no deadline: a server that never answered kept
 * the pool's slot for ever. The drivers bound it now
 * ({@code seclume.pool.probeSeconds}), and their deadline closes the
 * connection - which the pool must then not lend.
 */
class CapacityProbeTest {

    /** Connections whose capacity question is answered, or - the first - runs out of time. */
    private static final class Source implements DataSource {
        final AtomicInteger opened = new AtomicInteger();
        final List<AtomicBoolean> closed = new CopyOnWriteArrayList<>();
        final int silent;

        Source(int silent) {
            this.silent = silent;
        }

        @Override
        public Connection getConnection() {
            boolean timesOut = opened.getAndIncrement() < silent;
            AtomicBoolean gone = new AtomicBoolean();
            closed.add(gone);
            ServerCapacity capacity = () -> {
                if (timesOut) {
                    gone.set(true);              // the driver's deadline closed it
                    return new ServerCapacity.Capacity(-1, -1);
                }
                return new ServerCapacity.Capacity(100, 1);
            };
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, (self, method, args) ->
                            switch (method.getName()) {
                                case "isWrapperFor" -> args[0] == ServerCapacity.class;
                                case "unwrap" -> args[0] == ServerCapacity.class ? capacity : null;
                                case "isClosed" -> gone.get();
                                case "close" -> {
                                    gone.set(true);
                                    yield null;
                                }
                                case "isValid", "getAutoCommit" -> !gone.get();
                                case "hashCode" -> System.identityHashCode(self);
                                case "equals" -> self == args[0];
                                default -> method.getReturnType() == boolean.class ? false
                                        : method.getReturnType() == int.class ? 0 : null;
                            });
        }

        @Override
        public Connection getConnection(String user, String password) {
            throw new UnsupportedOperationException();
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
        }

        @Override
        public void setLoginTimeout(int seconds) {
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
        public <T> T unwrap(Class<T> type) {
            return null;
        }

        @Override
        public boolean isWrapperFor(Class<?> type) {
            return false;
        }
    }

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(1);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        settings.setValidationBypassWindow(Duration.ofMinutes(5));
        return settings;
    }

    @Test
    void aSilentProbeIsGivenUpOnAndNotLent() throws SQLException {
        Source source = new Source(1);
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            SQLException refused = assertThrows(SQLException.class, pool::getConnection);
            assertEquals("08006", refused.getSQLState(), String.valueOf(refused));
            assertTrue(source.closed.get(0).get(), "the probed connection was left open");
            try (Connection next = pool.getConnection()) {
                assertFalse(next.isClosed(), "the next connection is probed and lent");
            }
            assertEquals(2, source.opened.get());
        }
    }

    @Test
    void theProbeTimeoutIsConfigurable() throws Exception {
        // Read once, from seclume.pool.probeSeconds; five seconds unset.
        Class<?> capacities = Class.forName("space.seclume.internal.jdbc.Capacities");
        java.lang.reflect.Field seconds = capacities.getDeclaredField("PROBE_SECONDS");
        seconds.setAccessible(true);
        assertEquals(Integer.getInteger("seclume.pool.probeSeconds", 5), seconds.getInt(null));
    }
}
