package space.seclume.helidon;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import javax.sql.DataSource;

import jakarta.inject.Inject;
import jakarta.inject.Named;

import org.junit.jupiter.api.Test;

import io.helidon.microprofile.testing.AddConfig;
import io.helidon.microprofile.testing.AddExtension;
import io.helidon.microprofile.testing.DisableDiscovery;
import io.helidon.microprofile.testing.junit5.HelidonTest;

import space.seclume.field.FieldKeys;
import space.seclume.pool.SeclumePool;

/**
 * Helidon MP: the extension turns MicroProfile Config into a default and a
 * named {@code DataSource} and a {@link FieldKeys} bean, installed.
 */
@HelidonTest
@DisableDiscovery
@AddExtension(SeclumeCdiExtension.class)
@AddConfig(key = "seclume.datasources.default.url", value = "jdbc:seclume:stub://db/app?user=a&provider=file&path=/x")
@AddConfig(key = "seclume.datasources.default.pool.maximum-pool-size", value = "3")
@AddConfig(key = "seclume.datasources.orders.url", value = "jdbc:seclume:stub://db/orders?user=o&provider=file&path=/y")
@AddConfig(key = "seclume.field-encryption.keys.1.provider", value = "file")
@AddConfig(key = "seclume.field-encryption.keys.1.path", value = "target/seclume-helidon-cdi-key")
class SeclumeCdiExtensionTest {

    static {
        StubDriver.INSTANCE.urls.size();
        try {
            Files.createDirectories(Path.of("target"));
            Files.writeString(Path.of("target/seclume-helidon-cdi-key"),
                    Base64.getEncoder().encodeToString(new byte[32]));
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    @Inject
    DataSource primary;

    @Inject
    @Named("orders")
    DataSource orders;

    @Inject
    FieldKeys keys;

    @Test
    void theBeansAreThere() throws Exception {
        assertEquals("default", ((SeclumePool) primary).settings().getName());
        assertEquals(3, ((SeclumePool) primary).settings().getMaximumPoolSize());
        assertEquals("orders", ((SeclumePool) orders).settings().getName());
        assertNotSame(primary, orders);
        orders.getConnection().close();
        assertSame(keys, FieldKeys.installed());
        assertEquals(java.util.List.of(1), keys.keyIds());
    }
}
