package space.seclume.micronaut;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import io.micronaut.context.ApplicationContext;
import io.micronaut.inject.qualifiers.Qualifiers;

import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldKeys;
import space.seclume.pool.SeclumePool;

/**
 * seclume in a Micronaut application context, from properties only: named
 * pools over the driver the URL names, the key ring built and installed, and
 * a password in the configuration refused at start-up. The same against a
 * real PostgreSQL is {@link LocalMicronautPostgresTest}.
 *
 * <p>Isolated: the installed key ring is the process's.
 */
@Isolated
class SeclumeMicronautTest {

    /** A driver for {@code jdbc:seclume:stub:} whose connections answer what a pool asks. */
    static final class StubDriver implements Driver {
        final List<String> urls = new ArrayList<>();

        @Override
        public Connection connect(String url, Properties info) {
            if (!acceptsURL(url)) {
                return null;
            }
            urls.add(url);
            boolean[] closed = {false};
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, (proxy, method, args) -> switch (method.getName()) {
                        case "isValid" -> !closed[0];
                        case "isClosed" -> closed[0];
                        case "close", "abort" -> {
                            closed[0] = true;
                            yield null;
                        }
                        case "unwrap" -> throw new SQLException("not a wrapper");
                        case "getAutoCommit" -> true;
                        case "isReadOnly" -> false;
                        case "getTransactionIsolation" -> Connection.TRANSACTION_READ_COMMITTED;
                        case "getCatalog", "getSchema", "getWarnings" -> null;
                        case "getHoldability" -> java.sql.ResultSet.HOLD_CURSORS_OVER_COMMIT;
                        case "getNetworkTimeout" -> 0;
                        case "isWrapperFor" -> false;
                        case "hashCode" -> System.identityHashCode(proxy);
                        case "equals" -> proxy == args[0];
                        case "toString" -> "StubConnection";
                        case "setAutoCommit", "setReadOnly", "setTransactionIsolation", "clearWarnings",
                                "setCatalog", "setSchema", "rollback", "commit", "setHoldability",
                                "setNetworkTimeout" -> null;
                        default -> throw new SQLFeatureNotSupportedException(method.getName());
                    });
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

    private static final StubDriver DRIVER = new StubDriver();

    @TempDir
    Path directory;

    @BeforeAll
    static void register() throws SQLException {
        DriverManager.registerDriver(DRIVER);
    }

    @AfterAll
    static void deregister() throws SQLException {
        DriverManager.deregisterDriver(DRIVER);
    }

    private Path keyFile(String name, int seed) throws Exception {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (seed * 29 + i);
        }
        return Files.writeString(directory.resolve(name), Base64.getEncoder().encodeToString(key));
    }

    @Test
    void namedPoolsFromThePropertiesTheDefaultOnePrimary() throws Exception {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("seclume.datasources.default.url", "jdbc:seclume:stub://db/app?user=app&provider=file&path=/x");
        properties.put("seclume.datasources.default.pool.maximum-pool-size", "3");
        properties.put("seclume.datasources.orders.url", "jdbc:seclume:stub://db/orders?user=o&provider=file&path=/y");
        properties.put("seclume.datasources.orders.pool.connection-timeout", "2s");
        SeclumePool orders;
        try (ApplicationContext context = ApplicationContext.run(properties)) {
            SeclumePool primary = context.getBean(SeclumePool.class);
            assertEquals("default", primary.settings().getName());
            assertEquals(3, primary.settings().getMaximumPoolSize());
            orders = context.getBean(SeclumePool.class, Qualifiers.byName("orders"));
            assertEquals(java.time.Duration.ofSeconds(2), orders.settings().getConnectionTimeout());
            assertSame(primary, context.getBean(DataSource.class));
            try (Connection connection = orders.getConnection()) {
                assertFalse(connection.isClosed());
            }
            assertTrue(DRIVER.urls.contains("jdbc:seclume:stub://db/orders?user=o&provider=file&path=/y"));
        }
        assertThrows(SQLException.class, orders::getConnection, "closed with the context");
    }

    @Test
    void aWrongPoolSettingStopsTheStart() {
        Map<String, Object> properties = Map.of(
                "seclume.datasources.default.url", "jdbc:seclume:stub://db/app?user=app&provider=file&path=/x",
                "seclume.datasources.default.pool.max-pool-size", "3");
        RuntimeException e = assertThrows(RuntimeException.class, () -> {
            try (ApplicationContext context = ApplicationContext.run(properties)) {
                context.getBean(SeclumePool.class);
            }
        });
        assertTrue(chain(e).contains("no pool setting 'max-pool-size'"), chain(e));
    }

    @Test
    void theKeyRingIsBuiltInstalledAndWiped() throws Exception {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("seclume.field-encryption.keys.1.provider", "file");
        properties.put("seclume.field-encryption.keys.1.path", keyFile("k1", 1).toString());
        properties.put("seclume.field-encryption.keys.2.uri", "file:" + keyFile("k2", 2));
        properties.put("seclume.field-encryption.primary", "1");
        FieldKeys keys;
        try (ApplicationContext context = ApplicationContext.run(properties)) {
            keys = context.getBean(FieldKeys.class);
            assertSame(keys, FieldKeys.installed());
            assertEquals(1, keys.primary());
            assertEquals(List.of(1, 2), keys.keyIds());
            byte[] stored = keys.column("patient.ssn", Mode.DETERMINISTIC)
                    .encrypt(java.lang.foreign.MemorySegment.ofArray("123".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            assertEquals(1, keys.column("patient.ssn", Mode.DETERMINISTIC).keyId(stored));
        }
        assertThrows(IllegalStateException.class, FieldKeys::installed, "uninstalled when the context closed");
        assertThrows(IllegalStateException.class, () -> keys.column("x", Mode.RANDOMIZED), "and wiped");
    }

    @Test
    void anUnreadableKeyStopsTheStartAndNoKeysMeansNoRing() {
        Map<String, Object> properties = Map.of(
                "seclume.field-encryption.keys.1.provider", "file",
                "seclume.field-encryption.keys.1.path", directory.resolve("absent").toString());
        assertThrows(RuntimeException.class, () -> ApplicationContext.run(properties).close());
        try (ApplicationContext context = ApplicationContext.run(Map.of("app.name", "x"))) {
            assertNull(context.getBean(SeclumeFieldEncryption.class).keys());
            RuntimeException e = assertThrows(RuntimeException.class, () -> context.getBean(FieldKeys.class));
            assertTrue(chain(e).contains("no field encryption keys are configured"), chain(e));
        }
    }

    @Test
    void aPasswordInTheConfigurationStopsTheStart() {
        for (Map<String, Object> properties : List.<Map<String, Object>>of(
                Map.of("datasources.default.url", "jdbc:seclume:postgresql://db/app?user=app",
                        "datasources.default.password", "zl-micronaut-canary"),
                Map.of("seclume.datasources.orders.url", "jdbc:seclume:stub://db/x?user=a",
                        "seclume.datasources.orders.password", "zl-micronaut-canary"))) {
            RuntimeException e = assertThrows(RuntimeException.class, () -> ApplicationContext.run(properties).close());
            assertTrue(chain(e).contains("a password stands in the configuration"), chain(e));
            assertFalse(chain(e).contains("zl-micronaut-canary"), "the message carries the password");
        }
        // Another driver's data source with a password is not seclume's business.
        try (ApplicationContext context = ApplicationContext.run(Map.of(
                "datasources.legacy.url", "jdbc:h2:mem:x", "datasources.legacy.password", "sa"))) {
            assertTrue(context.isRunning());
        }
    }

    @Test
    void aUrlWithAPasswordIsRefused() {
        Map<String, Object> properties = Map.of("seclume.datasources.default.url",
                "jdbc:seclume:stub://db/app?user=app&password=zl-micronaut-canary");
        RuntimeException e = assertThrows(RuntimeException.class, () -> {
            try (ApplicationContext context = ApplicationContext.run(properties)) {
                context.getBean(SeclumePool.class);
            }
        });
        assertTrue(chain(e).contains("carries a password"), chain(e));
        assertFalse(chain(e).contains("zl-micronaut-canary"));
    }

    @Test
    void theKeyNamesAreGroupedByNumber() {
        Map<String, Object> nested = new LinkedHashMap<>();
        nested.put("1", Map.of("provider", "file", "path", "/a"));
        nested.put("2.uri", "file:/b");
        Map<Integer, Map<String, String>> keys = SeclumeFieldEncryption.keys(nested);
        assertEquals(Map.of("provider", "file", "path", "/a"), keys.get(1));
        assertEquals(Map.of("uri", "file:/b"), keys.get(2));
        assertThrows(IllegalArgumentException.class, () -> SeclumeFieldEncryption.keys(Map.of("one.provider", "file")));
        assertThrows(IllegalArgumentException.class, () -> SeclumeFieldEncryption.keys(Map.of("provider", "file")));
    }

    private static String chain(Throwable e) {
        StringBuilder all = new StringBuilder();
        for (Throwable t = e; t != null; t = t.getCause()) {
            all.append(t.getMessage()).append(" | ");
        }
        return all.toString();
    }
}
