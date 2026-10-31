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

    private static IllegalArgumentException refused(String url) {
        return assertThrows(IllegalArgumentException.class,
                () -> PoolConfiguration.pool("main", url, Map.of()).close(), url);
    }

    @Test
    void everyInlineSecretIsRefusedAndNeverRepeated() {
        String canary = "zlPoolCanary7f3e";
        for (String url : List.of(
                "jdbc:seclume:postgresql://db/app?password=" + canary,
                "jdbc:seclume:postgresql://db/app?user=a&password=" + canary,
                "jdbc:seclume:postgresql://db/app?user=a&PASSWORD=" + canary,
                "jdbc:seclume:postgresql://db/app?user=a&Password =" + canary,
                "jdbc:seclume:postgresql://db/app?user=a& password=" + canary,
                "jdbc:seclume:mysql://db/app?user=a&secret=" + canary,
                "jdbc:seclume:mysql://db/app?user=a&value=" + canary,
                "jdbc:seclume:sqlserver://db;user=a;password=" + canary,
                "jdbc:seclume:sqlserver://db;databaseName=x;Secret=" + canary,
                "jdbc:seclume:oracle://ora:1521/FREE?user=a&tls=off&password=" + canary + "&provider=file",
                "jdbc:seclume:postgresql://app:" + canary + "@db/app",
                "jdbc:seclume:postgresql://app:" + canary + "@db:5432/app?tls=off",
                "jdbc:seclume:sqlserver://sa:" + canary + "@db;databaseName=x")) {
            IllegalArgumentException e = refused(url);
            assertTrue(e.getMessage().contains("the URL carries a"), e.getMessage());
            assertFalse(e.getMessage().contains(canary), "the refusal repeats the secret: " + e.getMessage());
            assertTrue(e.getMessage().contains("provider=file"), "and says what to do instead");
        }
    }

    @Test
    void whatOnlyLooksLikeASecretIsLetThrough() {
        for (String url : List.of(
                "jdbc:seclume:postgresql://db/app?user=a&provider=file&path=/run/secrets/password",
                "jdbc:seclume:postgresql://db/app?user=a&provider=vault&address=https://vault:8200"
                        + "&path=secret/data/app&field=password&token-provider=file&token-path=/t",
                "jdbc:seclume:postgresql://db/app?user=a&client-secret-provider=file&client-secret-path=/s",
                "jdbc:seclume:postgresql://db/app?user=a&key-value-store=x",
                "jdbc:seclume:postgresql://app@db/app?provider=file&path=/p",
                "jdbc:seclume:postgresql://app@EXAMPLE.COM@db/app?auth=kerberos",
                "jdbc:seclume:postgresql://[::1]:5432/app?user=a&provider=file&path=/p",
                "jdbc:seclume:sqlserver://db:1433;databaseName=x;user=a;provider=file;path=/p")) {
            assertEquals(null, PoolConfiguration.inlineSecret(url), url);
        }
    }

    @Test
    void aUrlThatIsNotSeclumesIsNamedOnlyByItsScheme() {
        String canary = "zlRootCanary99";
        for (String url : List.of("jdbc:mysql://root:" + canary + "@db/app",
                "jdbc:postgresql://db/app?user=a&password=" + canary,
                "jdbc:sqlserver://db;user=sa;password=" + canary)) {
            IllegalArgumentException e = refused(url);
            assertTrue(e.getMessage().contains("a seclume URL"), e.getMessage());
            assertFalse(e.getMessage().contains(canary), "the refusal repeats the secret: " + e.getMessage());
            String given = e.getMessage().substring(e.getMessage().lastIndexOf(" not ") + 5);
            assertTrue(given.matches("jdbc:[a-z]+:\\.\\.\\."), "nothing after the scheme: " + given);
        }
        assertEquals("jdbc:mysql:", PoolConfiguration.scheme("jdbc:mysql://root:x@db"));
        assertEquals("something that is no JDBC URL", PoolConfiguration.scheme("geheim"));
        assertEquals("something that is no JDBC URL", PoolConfiguration.scheme("geheim:" + canary));
        assertFalse(refused("").getMessage().contains(canary));
        assertTrue(refused(null).getMessage().contains("none"));
    }

    @Test
    void durationsInEveryWrittenForm() {
        Map<String, Duration> forms = new LinkedHashMap<>();
        forms.put("0", Duration.ZERO);
        forms.put("1ms", Duration.ofMillis(1));
        forms.put("250MS", Duration.ofMillis(250));
        forms.put("30s", Duration.ofSeconds(30));
        forms.put(" 30s ", Duration.ofSeconds(30));
        forms.put("30S", Duration.ofSeconds(30));
        forms.put("10m", Duration.ofMinutes(10));
        forms.put("2h", Duration.ofHours(2));
        forms.put("7d", Duration.ofDays(7));
        forms.put("PT45S", Duration.ofSeconds(45));
        forms.put("pt1m30s", Duration.ofSeconds(90));
        forms.put("P1D", Duration.ofDays(1));
        forms.put("PT0S", Duration.ZERO);
        for (Map.Entry<String, Duration> form : forms.entrySet()) {
            assertEquals(form.getValue(), PoolConfiguration.settings("d",
                    Map.of("max-lifetime", form.getKey())).getMaxLifetime(), "'" + form.getKey() + "'");
        }
        for (String wrong : List.of("", " ", "s", "ms", "10", "1.5s", "10 s", "ten s", "10w", "P", "PTXS",
                "99999999999999999999s", "--1s", "1e3ms")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> PoolConfiguration.settings("d", Map.of("idle-timeout", wrong)), "'" + wrong + "'");
            assertTrue(e.getMessage().startsWith("pool.idle-timeout is a duration"), e.getMessage());
            assertTrue(e.getMessage().contains("'" + wrong.trim() + "'"), "names what it was given: " + e.getMessage());
        }
    }

    @Test
    void numbersAndSwitches() {
        assertEquals(12, PoolConfiguration.settings("n", Map.of("maximum-pool-size", " 12 ")).getMaximumPoolSize());
        for (String wrong : List.of("", "7.0", "3000000000", "0x10", "1_000", "+-3")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> PoolConfiguration.settings("n", Map.of("statement-cache-size", wrong)), wrong);
            assertTrue(e.getMessage().contains("is a whole number"), e.getMessage());
        }
        for (String yes : List.of("true", "TRUE", "yes", "On", " on ")) {
            assertTrue(PoolConfiguration.settings("b", Map.of("warmup", yes)).isWarmup(), yes);
        }
        for (String no : List.of("false", "No", "OFF")) {
            assertFalse(PoolConfiguration.settings("b", Map.of("warmup", no)).isWarmup(), no);
        }
        for (String wrong : List.of("1", "0", "y", "", "enabled")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> PoolConfiguration.settings("b", Map.of("warmup", wrong)), wrong);
            assertTrue(e.getMessage().contains("is true or false"), e.getMessage());
        }
    }

    @Test
    void keysInEverySpellingAFrameworkUses() {
        for (String key : List.of("minimum-idle", "minimumIdle", "minimum_idle", "MINIMUM_IDLE",
                "Minimum-Idle", " minimum-idle ", "MinimumIdle")) {
            assertEquals(3, PoolConfiguration.settings("k", Map.of(key, "3")).getMinimumIdle(), "'" + key + "'");
        }
        Map<String, String> withNull = new java.util.HashMap<>();
        withNull.put("minimum-idle", null);
        assertThrows(IllegalArgumentException.class, () -> PoolConfiguration.settings("k", withNull),
                "a key without a value is an error, not the default");
        IllegalArgumentException unknown = assertThrows(IllegalArgumentException.class,
                () -> PoolConfiguration.settings("k", Map.of("maxPoolSize", "zlUnknownValue")));
        assertTrue(unknown.getMessage().contains("'maxPoolSize'"), unknown.getMessage());
        assertTrue(unknown.getMessage().contains("maximum-pool-size"), "lists what there is: " + unknown.getMessage());
        assertFalse(unknown.getMessage().contains("zlUnknownValue"), "and not the value");
        for (String key : PoolConfiguration.KEYS) {
            assertTrue(unknown.getMessage().contains(key), key + " missing from " + unknown.getMessage());
        }
    }

    @Test
    void toStringNeverShowsTheSettings() {
        for (String url : List.of("jdbc:seclume:postgresql://db/app?user=a&provider=vault&path=secret/x",
                "jdbc:seclume:sqlserver://db:1433;databaseName=x;provider=vault;path=secret/x",
                "jdbc:seclume:mysql://db/app;provider=file?path=secret/x")) {
            String shown = new PoolConfiguration.UrlDataSource(url).toString();
            assertFalse(shown.contains("provider"), shown);
            assertFalse(shown.contains("secret/x"), shown);
            assertTrue(shown.startsWith("UrlDataSource[jdbc:seclume:"), shown);
        }
        assertEquals("UrlDataSource[jdbc:seclume:sqlserver://db:1433]",
                new PoolConfiguration.UrlDataSource("jdbc:seclume:sqlserver://db:1433;user=sa").toString());
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
