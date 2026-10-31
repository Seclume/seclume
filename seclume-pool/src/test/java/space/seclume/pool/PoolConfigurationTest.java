package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;

/** Pool settings from configuration keys, and a pool over the driver a URL names. */
class PoolConfigurationTest {

    @Test
    void everyKeyReachesItsSetting() {
        Map<String, String> pool = new LinkedHashMap<>();
        pool.put("maximum-pool-size", "7");
        pool.put("minimum-idle", "2");
        pool.put("connection-timeout", "15s");
        pool.put("idle-timeout", "5m");
        pool.put("max-lifetime", "PT1H");
        pool.put("keepalive-time", "0");
        pool.put("validation-timeout", "250ms");
        pool.put("leak-detection-threshold", "2h");
        pool.put("shutdown-timeout", "1d");
        pool.put("statement-cache-size", "0");
        pool.put("WARMUP", "true");
        assertEquals(9, PoolConfiguration.settings("c", Map.of("maximumPoolSize", "9")).getMaximumPoolSize());
        assertEquals(8, PoolConfiguration.settings("s", Map.of("maximum_pool_size", "8")).getMaximumPoolSize());
        PoolSettings settings = PoolConfiguration.settings("orders", pool);
        assertEquals("orders", settings.getName());
        assertEquals(7, settings.getMaximumPoolSize());
        assertEquals(2, settings.getMinimumIdle());
        assertEquals(Duration.ofSeconds(15), settings.getConnectionTimeout());
        assertEquals(Duration.ofMinutes(5), settings.getIdleTimeout());
        assertEquals(Duration.ofHours(1), settings.getMaxLifetime());
        assertEquals(Duration.ZERO, settings.getKeepaliveTime());
        assertEquals(Duration.ofMillis(250), settings.getValidationTimeout());
        assertEquals(Duration.ofHours(2), settings.getLeakDetectionThreshold());
        assertEquals(Duration.ofDays(1), settings.getShutdownTimeout());
        assertEquals(0, settings.getStatementCacheSize());
        assertTrue(settings.isWarmup());
        assertEquals(PoolConfiguration.KEYS.size(), pool.size(), "every key is in the test");
    }

    @Test
    void theDefaultsStayWhereNothingIsSaid() {
        PoolSettings settings = PoolConfiguration.settings("x", Map.of());
        PoolSettings plain = new PoolSettings();
        assertEquals(plain.getMaximumPoolSize(), settings.getMaximumPoolSize());
        assertEquals(plain.getConnectionTimeout(), settings.getConnectionTimeout());
        assertFalse(settings.isWarmup());
    }

    @Test
    void wrongKeysAndValuesSayWhat() {
        for (Map<String, String> wrong : List.of(Map.of("max-pool-size", "1"),
                Map.of("maximum-pool-size", "ten"), Map.of("idle-timeout", "soon"),
                Map.of("idle-timeout", "10x"), Map.of("idle-timeout", ""), Map.of("warmup", "maybe"),
                Map.of("password", "geheim"))) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> PoolConfiguration.settings("x", wrong), wrong.toString());
            assertFalse(e.getMessage().contains("geheim"), e.getMessage());
        }
    }

    @Test
    void aUrlWithAPasswordOrNotSeclumesIsRefused() {
        IllegalArgumentException password = assertThrows(IllegalArgumentException.class,
                () -> PoolConfiguration.pool("main", "jdbc:seclume:postgresql://db/app?user=a&password=geheim", Map.of()));
        assertTrue(password.getMessage().contains("carries a password"), password.getMessage());
        assertFalse(password.getMessage().contains("geheim"));
        assertThrows(IllegalArgumentException.class,
                () -> PoolConfiguration.pool("main", "jdbc:seclume:sqlserver://db;user=a;Password=x", Map.of()));
        assertThrows(IllegalArgumentException.class,
                () -> PoolConfiguration.pool("main", "jdbc:postgresql://db/app", Map.of()));
        assertThrows(IllegalArgumentException.class, () -> PoolConfiguration.pool("main", null, Map.of()));
    }

    /** A driver for {@code jdbc:seclume:stub:} that hands out the stub's connections. */
    static final class StubDriver implements Driver {
        final List<String> urls = new ArrayList<>();
        final StubDataSource stub = new StubDataSource();

        @Override
        public Connection connect(String url, Properties info) throws SQLException {
            if (!acceptsURL(url)) {
                return null;
            }
            urls.add(url);
            return stub.getConnection();
        }

        @Override
        public boolean acceptsURL(String url) {
            return url != null && url.startsWith("jdbc:seclume:stub:");
        }

        @Override
        public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
            return new DriverPropertyInfo[0];
        }

        @Override
        public int getMajorVersion() {
            return 1;
        }

        @Override
        public int getMinorVersion() {
            return 0;
        }

        @Override
        public boolean jdbcCompliant() {
            return false;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException("none");
        }
    }

    @Test
    void thePoolConnectsThroughTheDriverTheUrlNames() throws Exception {
        StubDriver driver = new StubDriver();
        DriverManager.registerDriver(driver);
        try (SeclumePool pool = PoolConfiguration.pool("stubbed",
                "jdbc:seclume:stub://db/app?user=app&provider=file&path=/run/secrets/db",
                Map.of("maximum-pool-size", "2"))) {
            assertTrue(driver.urls.isEmpty(), "nothing connects before it is asked");
            try (Connection connection = pool.getConnection()) {
                assertFalse(connection.isClosed());
            }
            assertEquals(1, driver.urls.size());
            assertEquals(2, pool.settings().getMaximumPoolSize());
            assertEquals("stubbed", pool.settings().getName());
            PoolConfiguration.UrlDataSource source = new PoolConfiguration.UrlDataSource(
                    "jdbc:seclume:stub://db/app?user=app&provider=file&path=/x");
            assertEquals("UrlDataSource[jdbc:seclume:stub://db/app]", source.toString(),
                    "the query - provider settings - stays out of toString");
            assertThrows(SQLFeatureNotSupportedException.class, () -> source.getConnection("u", "p"));
        } finally {
            DriverManager.deregisterDriver(driver);
        }
    }
}
