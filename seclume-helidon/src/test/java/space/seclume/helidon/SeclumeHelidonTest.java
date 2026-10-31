package space.seclume.helidon;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import io.helidon.config.Config;
import io.helidon.config.ConfigSources;

import space.seclume.field.FieldKeys;
import space.seclume.pool.SeclumePool;

/** Helidon SE: pools and the key ring from {@code Config}, closed and wiped together. */
@Isolated
class SeclumeHelidonTest {

    @TempDir
    Path directory;

    static {
        StubDriver.INSTANCE.urls.size();
    }

    private static Config config(Map<String, String> values) {
        return Config.just(ConfigSources.create(values));
    }

    @Test
    void poolsAndKeysFromConfig() throws Exception {
        byte[] key = new byte[32];
        Path file = Files.writeString(directory.resolve("key"), Base64.getEncoder().encodeToString(key));
        SeclumePool orders;
        FieldKeys keys;
        try (SeclumeHelidon seclume = SeclumeHelidon.create(config(Map.of(
                "seclume.datasources.orders.url", "jdbc:seclume:stub://db/orders?user=o&provider=file&path=/y",
                "seclume.datasources.orders.pool.maximum-pool-size", "2",
                "seclume.field-encryption.keys.1.provider", "file",
                "seclume.field-encryption.keys.1.path", file.toString())))) {
            orders = seclume.dataSource("orders");
            assertEquals(2, orders.settings().getMaximumPoolSize());
            orders.getConnection().close();
            keys = seclume.fieldKeys();
            assertSame(keys, FieldKeys.installed());
            assertThrows(IllegalArgumentException.class, () -> seclume.dataSource("billing"));
        }
        assertThrows(SQLException.class, orders::getConnection, "closed");
        assertNull(FieldKeys.installed(), "and the ring uninstalled with its close");
    }

    @Test
    void aPasswordInTheConfigurationIsRefused() {
        assertThrows(IllegalStateException.class, () -> SeclumeHelidon.create(config(Map.of(
                "seclume.datasources.orders.url", "jdbc:seclume:stub://db/o?user=o",
                "seclume.datasources.orders.password", "x"))));
    }

    @Test
    void nothingConfiguredIsNothingMade() throws Exception {
        try (SeclumeHelidon seclume = SeclumeHelidon.create(config(Map.of("server.port", "8080")))) {
            assertEquals(Map.of(), seclume.dataSources());
            assertNull(seclume.fieldKeys());
        }
    }
}
