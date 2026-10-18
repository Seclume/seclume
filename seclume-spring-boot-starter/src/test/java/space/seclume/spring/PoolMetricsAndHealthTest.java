package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.List;
import java.util.logging.Logger;

import javax.sql.DataSource;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;

/**
 * The two things an operations team asks for first: a dashboard and a health
 * check. Both are built on numbers the pool already had - what is new is that
 * they arrive without anybody writing glue code.
 */
class PoolMetricsAndHealthTest {

    @Test
    void theGaugesCarryThePoolsNumbers() throws Exception {
        try (SeclumePool pool = pool("metered")) {
            MeterRegistry registry = new SimpleMeterRegistry();
            new SeclumePoolMetrics(List.of(pool), false).bindTo(registry);

            try (Connection held = pool.getConnection()) {
                assertNotNull(held);
                assertEquals(1, value(registry, "seclume.pool.connections.active"));
                assertEquals(0, value(registry, "seclume.pool.connections.idle"));
            }
            assertEquals(0, value(registry, "seclume.pool.connections.active"));
            assertEquals(1, value(registry, "seclume.pool.connections.idle"));
            assertEquals(1, value(registry, "seclume.pool.borrowed"));

            // Off by default: a meter called hikaricp that is not HikariCP has
            // to be a deliberate choice.
            assertNull(registry.find("hikaricp.connections.active").gauge());
        }
    }

    /** For whoever migrates and wants to keep their dashboards. */
    @Test
    void theHikariNamesAppearWhenTheyAreAskedFor() throws Exception {
        try (SeclumePool pool = pool("compatible")) {
            MeterRegistry registry = new SimpleMeterRegistry();
            new SeclumePoolMetrics(List.of(pool), true).bindTo(registry);
            assertNotNull(registry.find("hikaricp.connections.active").gauge());
            assertEquals(value(registry, "seclume.pool.connections.idle"),
                    value(registry, "hikaricp.connections.idle"));
        }
    }

    @Test
    void theHealthCheckBorrowsAConnectionAndReportsTheState() throws Exception {
        try (SeclumePool pool = pool("healthy")) {
            Health health = new SeclumePoolHealth(List.of(pool)).health();
            assertEquals(Status.UP, health.getStatus());
            String detail = String.valueOf(health.getDetails().get("healthy"));
            assertTrue(detail.contains("in use"), detail);
            assertTrue(detail.contains("timeouts so far"), detail);
        }
    }

    /** A pool that hands out nothing is not healthy, and says why. */
    @Test
    void aPoolThatCannotHandOutAnythingIsDown() throws Exception {
        PoolSettings settings = new PoolSettings();
        settings.setName("stuck");
        settings.setMaximumPoolSize(1);
        settings.setConnectionTimeout(java.time.Duration.ofMillis(120));
        try (SeclumePool pool = new SeclumePool(new OneConnection(), settings);
             Connection held = pool.getConnection()) {
            assertNotNull(held);
            Health health = new SeclumePoolHealth(List.of(pool)).health();
            assertEquals(Status.DOWN, health.getStatus());
            assertTrue(String.valueOf(health.getDetails().get("stuck")).contains("in use"));
        }
    }

    private static SeclumePool pool(String name) {
        PoolSettings settings = new PoolSettings();
        settings.setName(name);
        settings.setMaximumPoolSize(2);
        settings.setConnectionTimeout(java.time.Duration.ofSeconds(2));
        return new SeclumePool(new OneConnection(), settings);
    }

    private static double value(MeterRegistry registry, String name) {
        Gauge gauge = registry.find(name).gauge();
        if (gauge != null) {
            return gauge.value();
        }
        io.micrometer.core.instrument.FunctionCounter counter =
                registry.find(name).functionCounter();
        assertNotNull(counter, "no gauge or counter named " + name);
        return counter.count();
    }

    /**
     * Closing the binder - Spring does it when the context closes - takes its
     * timers off the pool: a pool that outlives the context records nothing
     * more into the old registry.
     */
    @Test
    void closingTheBinderStopsTheTimers() throws Exception {
        try (SeclumePool pool = pool("refreshed")) {
            MeterRegistry registry = new SimpleMeterRegistry();
            SeclumePoolMetrics metrics = new SeclumePoolMetrics(List.of(pool), false);
            metrics.bindTo(registry);
            pool.getConnection().close();
            io.micrometer.core.instrument.Timer acquire =
                    registry.find("seclume.pool.acquire").timer();
            assertEquals(1, acquire.count());

            metrics.close();
            pool.getConnection().close();
            assertEquals(1, acquire.count(), "the closed binder's timer still records");
        }
    }

    /**
     * The durations as timers, the maximum as configured, and what only grows
     * as a counter - the three things a dashboard built on these got wrong
     * or could not have.
     */
    @Test
    void theTimersTheMaximumAndTheCounters() throws Exception {
        try (SeclumePool pool = pool("timed")) {
            MeterRegistry registry = new SimpleMeterRegistry();
            new SeclumePoolMetrics(List.of(pool), true).bindTo(registry);
            assertEquals(2, value(registry, "seclume.pool.connections.max"),
                    "the maximum is the configured one, not the connections held");

            try (Connection held = pool.getConnection()) {
                assertNotNull(held);
                Thread.sleep(5);
            }
            try (Connection again = pool.getConnection()) {
                assertNotNull(again);
            }
            io.micrometer.core.instrument.Timer acquire =
                    registry.find("seclume.pool.acquire").timer();
            io.micrometer.core.instrument.Timer usage =
                    registry.find("seclume.pool.usage").timer();
            io.micrometer.core.instrument.Timer creation =
                    registry.find("seclume.pool.creation").timer();
            assertEquals(2, acquire.count());
            assertEquals(2, usage.count());
            assertEquals(1, creation.count(), "one connection was opened, then reused");
            assertTrue(usage.max(java.util.concurrent.TimeUnit.MILLISECONDS) >= 4,
                    "the hold of five milliseconds was not timed");
            assertEquals(2, registry.find("hikaricp.connections.acquire").timer().count());

            assertNotNull(registry.find("seclume.pool.borrowed").functionCounter(),
                    "a number that only grows is a counter");
            assertEquals(2, value(registry, "seclume.pool.borrowed"));
            assertEquals(0, value(registry, "seclume.pool.resets.refused"));
        }
    }

    /** A data source that hands out connections which do nothing. */
    private static final class OneConnection implements DataSource {

        @Override
        public Connection getConnection() {
            return (Connection) java.lang.reflect.Proxy.newProxyInstance(
                    OneConnection.class.getClassLoader(), new Class<?>[] {Connection.class},
                    (proxy, method, arguments) -> switch (method.getName()) {
                        case "isClosed" -> false;
                        case "isValid" -> true;
                        case "getAutoCommit" -> true;
                        case "isReadOnly" -> false;
                        case "getTransactionIsolation" -> Connection.TRANSACTION_READ_COMMITTED;
                        case "toString" -> "stub connection";
                        case "hashCode" -> System.identityHashCode(proxy);
                        case "equals" -> proxy == arguments[0];
                        default -> null;
                    });
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            throw new SQLFeatureNotSupportedException("this stub takes no password at all");
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
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException("this stub does not log");
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            throw new SQLException("this stub is not a wrapper for " + iface.getName());
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return false;
        }
    }
}
