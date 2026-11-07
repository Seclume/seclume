package space.seclume.helidon;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.field.FieldKeys;
import space.seclume.pool.SeclumePool;

/** The configuration as seclume reads it, whichever Helidon holds it. */
class SeclumeSettingsTest {

    @TempDir
    Path directory;

    static {
        StubDriver.INSTANCE.urls.size();
    }

    @Test
    void dataSourcesByNameWithTheirPools() throws Exception {
        Map<String, String> all = new LinkedHashMap<>();
        all.put("seclume.datasources.default.url", "jdbc:seclume:stub://db/app?user=a&provider=file&path=/x");
        all.put("seclume.datasources.default.pool.maximum-pool-size", "4");
        all.put("seclume.datasources.orders.url", "jdbc:seclume:stub://db/orders?user=o&provider=file&path=/y");
        all.put("server.port", "8080");
        SeclumeSettings settings = SeclumeSettings.of(all);
        assertEquals(List.of("default", "orders"), List.copyOf(settings.dataSources().keySet()));
        Map<String, SeclumePool> pools = settings.pools();
        try {
            assertEquals(4, pools.get("default").settings().getMaximumPoolSize());
            assertEquals("orders", pools.get("orders").settings().getName());
            try (Connection connection = pools.get("orders").getConnection()) {
                assertFalse(connection.isClosed());
            }
        } finally {
            pools.values().forEach(SeclumePool::close);
        }
    }

    @Test
    void anUnknownSettingOrAPasswordUrlIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> SeclumeSettings.of(Map.of(
                "seclume.datasources.default.url", "jdbc:seclume:stub://db/x?user=a",
                "seclume.datasources.default.max-size", "3")).pools());
        assertThrows(IllegalArgumentException.class, () -> SeclumeSettings.of(Map.of(
                "seclume.datasources.default.url", "jdbc:seclume:stub://db/x?user=a&password=x")).pools());
        assertThrows(IllegalArgumentException.class, () -> SeclumeSettings.of(Map.of(
                "seclume.datasources.default.url", "jdbc:seclume:stub://db/x?user=a",
                "seclume.datasources.default.pool.warmup", "perhaps")).pools());
    }

    private Path keyFile(String name, int seed) throws Exception {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (seed * 19 + i);
        }
        return Files.writeString(directory.resolve(name), Base64.getEncoder().encodeToString(key));
    }

    @Test
    void theKeyRingFromProviderSettingsAndUris() throws Exception {
        Map<String, String> all = new LinkedHashMap<>();
        all.put("seclume.field-encryption.keys.1.provider", "file");
        all.put("seclume.field-encryption.keys.1.path", keyFile("k1", 1).toString());
        all.put("seclume.field-encryption.keys.2.uri", "file:" + keyFile("k2", 2));
        all.put("seclume.field-encryption.primary", "1");
        try (FieldKeys keys = SeclumeSettings.of(all).fieldKeys()) {
            assertEquals(List.of(1, 2), keys.keyIds());
            assertEquals(1, keys.primary());
        }
        assertNull(SeclumeSettings.of(Map.of("server.port", "1")).fieldKeys());
        assertThrows(IllegalArgumentException.class, () -> SeclumeSettings.of(Map.of(
                "seclume.field-encryption.keys.one.provider", "file")).fieldKeys());
        assertThrows(IllegalArgumentException.class, () -> SeclumeSettings.of(Map.of(
                "seclume.field-encryption.keys.1", "file")).fieldKeys());
        assertThrows(RuntimeException.class, () -> SeclumeSettings.of(Map.of(
                "seclume.field-encryption.keys.1.provider", "file",
                "seclume.field-encryption.keys.1.path", directory.resolve("absent").toString())).fieldKeys());
    }

    @Test
    void passwordsWhereSeclumeWouldHaveKeptThemOffTheHeap() {
        Map<String, String> all = new LinkedHashMap<>();
        all.put("javax.sql.DataSource.app.dataSource.url", "jdbc:seclume:postgresql://db/app?user=app");
        all.put("javax.sql.DataSource.app.dataSource.password", "zl-helidon-canary");
        all.put("javax.sql.DataSource.legacy.dataSource.url", "jdbc:h2:mem:x");
        all.put("javax.sql.DataSource.legacy.dataSource.password", "sa");
        all.put("seclume.datasources.orders.password", "zl-helidon-canary");
        SeclumeSettings settings = SeclumeSettings.of(all);
        assertEquals(List.of("javax.sql.DataSource.app.dataSource.password", "seclume.datasources.orders.password"),
                settings.passwords().stream().sorted().toList());
        IllegalStateException e = assertThrows(IllegalStateException.class, settings::refusePasswords);
        assertTrue(e.getMessage().contains("a password stands in the configuration"), e.getMessage());
        assertFalse(e.getMessage().contains("zl-helidon-canary"));
        SeclumeSettings.of(Map.of("javax.sql.DataSource.legacy.dataSource.url", "jdbc:h2:mem:x",
                "javax.sql.DataSource.legacy.dataSource.password", "sa")).refusePasswords();
    }

    /**
     * As environment variables, the way a container passes a password:
     * MicroProfile Config reads {@code JAVAX_SQL_DATASOURCE_APP_DATASOURCE_PASSWORD}
     * as {@code javax.sql.DataSource.app.dataSource.password}, the same
     * {@code String} on the heap - and the environment's source lists it by
     * its own name, which the check never matched.
     */
    @Test
    void passwordsInEnvironmentVariables() {
        Map<String, String> all = new LinkedHashMap<>();
        all.put("JAVAX_SQL_DATASOURCE_APP_DATASOURCE_URL", "jdbc:seclume:postgresql://db/app?user=app");
        all.put("JAVAX_SQL_DATASOURCE_APP_DATASOURCE_PASSWORD", "zl-helidon-canary");
        all.put("javax.sql.DataSource.app-db.dataSource.url", "jdbc:seclume:mysql://db/app?user=app");
        all.put("JAVAX_SQL_DATASOURCE_APP_DB_PASSWORD", "zl-helidon-canary");
        all.put("JAVAX_SQL_DATASOURCE_LEGACY_DATASOURCE_URL", "jdbc:h2:mem:x");
        all.put("JAVAX_SQL_DATASOURCE_LEGACY_DATASOURCE_PASSWORD", "sa");
        all.put("SECLUME_DATASOURCES_ORDERS_PASSWORD", "zl-helidon-canary");
        all.put("SECLUME_RABBITMQ_PASSWORD_FILE", "/run/secrets/rabbit");
        SeclumeSettings settings = SeclumeSettings.of(all);
        assertEquals(List.of("JAVAX_SQL_DATASOURCE_APP_DATASOURCE_PASSWORD", "JAVAX_SQL_DATASOURCE_APP_DB_PASSWORD",
                "SECLUME_DATASOURCES_ORDERS_PASSWORD"), settings.passwords().stream().sorted().toList());
        IllegalStateException e = assertThrows(IllegalStateException.class, settings::refusePasswords);
        assertFalse(e.getMessage().contains("zl-helidon-canary"), e.getMessage());
        assertEquals(Map.of(), settings.dataSources(), "an environment variable's name is not a data source");
    }

    @Test
    void aDottedPasswordBesideAnEnvironmentVariablesUrl() {
        assertEquals(List.of("javax.sql.DataSource.app.dataSource.password"), SeclumeSettings.of(Map.of(
                "JAVAX_SQL_DATASOURCE_APP_DATASOURCE_URL", "jdbc:seclume:postgresql://db/app?user=app",
                "javax.sql.DataSource.app.dataSource.password", "zl-helidon-canary")).passwords());
    }
}
