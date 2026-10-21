package space.seclume.opentelemetry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.time.Duration;
import java.util.Collection;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.HistogramPointData;
import io.opentelemetry.sdk.metrics.data.LongPointData;
import io.opentelemetry.sdk.metrics.data.MetricData;
import io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader;

import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;

/**
 * A real pool over connections that need no database, read through the
 * semantic conventions for connection pools: the counts by state, the
 * limits, the times - and nothing once the instruments are closed.
 */
class SeclumePoolInstrumentsTest {

    private static final AttributeKey<String> POOL =
            AttributeKey.stringKey("db.client.connection.pool.name");
    private static final AttributeKey<String> STATE =
            AttributeKey.stringKey("db.client.connection.state");

    @Test
    void thePoolIsReadUnderTheConventions() throws Exception {
        InMemoryMetricReader reader = InMemoryMetricReader.create();
        PoolSettings settings = new PoolSettings();
        settings.setName("orders");
        settings.setMaximumPoolSize(4);
        settings.setMinimumIdle(1);
        settings.setConnectionTimeout(Duration.ofSeconds(5));
        try (OpenTelemetrySdk sdk = OpenTelemetrySdk.builder().setMeterProvider(
                     SdkMeterProvider.builder().registerMetricReader(reader).build()).build();
             SeclumePool pool = new SeclumePool(new Connections(), settings)) {
            AutoCloseable instruments = SeclumePoolInstruments.observe(sdk, pool);
            try (Connection first = pool.getConnection();
                 Connection second = pool.getConnection()) {
                assertTrue(first.isValid(1) && second.isValid(1));
                Collection<MetricData> now = reader.collectAllMetrics();
                assertEquals(2, count(now, "used"), "two lent out");
                assertEquals(4, single(now, "db.client.connection.max"));
                assertEquals(1, single(now, "db.client.connection.idle.min"));
                assertEquals(0, single(now, "db.client.connection.pending_requests"));
            }
            Collection<MetricData> after = reader.collectAllMetrics();
            assertEquals(0, count(after, "used"));
            assertTrue(count(after, "idle") >= 2, "both came back");
            for (String time : new String[] {"db.client.connection.wait_time",
                    "db.client.connection.use_time", "db.client.connection.create_time"}) {
                MetricData histogram = metric(after, time);
                assertEquals("s", histogram.getUnit(), time);
                HistogramPointData point = histogram.getHistogramData().getPoints()
                        .iterator().next();
                assertTrue(point.getCount() >= 2, time + ": " + point.getCount());
                assertEquals("orders", point.getAttributes().get(POOL));
            }

            instruments.close();
            try (Connection third = pool.getConnection()) {
                assertTrue(third.isValid(1));
            }
            assertTrue(reader.collectAllMetrics().stream()
                    .noneMatch(m -> m.getName().equals("db.client.connection.count")
                            && !m.getLongSumData().getPoints().isEmpty()
                            && m.getLongSumData().getPoints().stream()
                                    .anyMatch(p -> p.getAttributes().get(STATE) != null
                                            && "used".equals(p.getAttributes().get(STATE))
                                            && p.getValue() == 1)),
                    "closed instruments are still observed");
        }
    }

    private static long count(Collection<MetricData> metrics, String state) {
        MetricData data = metric(metrics, "db.client.connection.count");
        assertEquals("{connection}", data.getUnit());
        return data.getLongSumData().getPoints().stream()
                .filter(p -> state.equals(p.getAttributes().get(STATE)))
                .filter(p -> "orders".equals(p.getAttributes().get(POOL)))
                .mapToLong(LongPointData::getValue).sum();
    }

    private static long single(Collection<MetricData> metrics, String name) {
        LongPointData point = metric(metrics, name).getLongSumData().getPoints().iterator().next();
        assertEquals(Attributes.of(POOL, "orders"), point.getAttributes());
        return point.getValue();
    }

    private static MetricData metric(Collection<MetricData> metrics, String name) {
        return metrics.stream().filter(m -> m.getName().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError(name + " is missing: " + metrics));
    }

    /** Connections that answer like an idle session and need no server. */
    private static final class Connections implements DataSource {

        @Override
        public Connection getConnection() {
            AtomicBoolean closed = new AtomicBoolean();
            return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                    new Class<?>[] {Connection.class}, (proxy, method, args) -> switch (
                            method.getName()) {
                        case "isValid" -> !closed.get();
                        case "isClosed" -> closed.get();
                        case "close" -> {
                            closed.set(true);
                            yield null;
                        }
                        case "getAutoCommit" -> true;
                        case "isReadOnly", "isWrapperFor" -> false;
                        case "getTransactionIsolation" -> Connection.TRANSACTION_READ_COMMITTED;
                        case "getNetworkTimeout", "getHoldability" -> 0;
                        case "unwrap" -> throw new SQLException("not a wrapper");
                        case "hashCode" -> System.identityHashCode(proxy);
                        case "equals" -> proxy == args[0];
                        case "toString" -> "test connection";
                        default -> null;
                    });
        }

        @Override
        public Connection getConnection(String user, String password) {
            return getConnection();
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
            throw new SQLFeatureNotSupportedException();
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
}
