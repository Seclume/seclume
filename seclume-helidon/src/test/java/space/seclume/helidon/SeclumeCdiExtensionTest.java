package space.seclume.helidon;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.sql.DataSource;

import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.literal.NamedLiteral;
import jakarta.enterprise.inject.se.SeContainer;
import jakarta.enterprise.inject.se.SeContainerInitializer;
import jakarta.enterprise.inject.spi.Extension;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.ConfigValue;
import org.eclipse.microprofile.config.spi.ConfigProviderResolver;
import org.eclipse.microprofile.config.spi.ConfigSource;
import org.eclipse.microprofile.config.spi.Converter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.field.FieldKeys;
import space.seclume.pool.SeclumePool;

/**
 * Helidon MP: the extension, found by the service loader as in an
 * application, turns MicroProfile Config into a default and a named
 * {@code DataSource} and a {@link FieldKeys} bean, installed - in a Helidon
 * CDI container started here, with bean discovery off and the configuration
 * registered for this class loader, so that what the extension was given can
 * be checked before the container is.
 *
 * <p>Isolated: the container, the registered configuration and the installed
 * ring are each one per JVM.
 */
@Isolated
class SeclumeCdiExtensionTest {

    private static Path keyFile;
    private static SeContainer container;

    /** A config source of a map, as an application's properties file is one. */
    record MapSource(String name, int ordinal, Map<String, String> properties) implements ConfigSource {
        @Override
        public Map<String, String> getProperties() {
            return properties;
        }

        @Override
        public Set<String> getPropertyNames() {
            return properties.keySet();
        }

        @Override
        public String getValue(String key) {
            return properties.get(key);
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public int getOrdinal() {
            return ordinal;
        }
    }

    static Map<String, String> settings() {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("mp.initializer.allow", "true");
        settings.put("mp.initializer.no-warn", "true");
        settings.put("seclume.datasources.default.url", "jdbc:seclume:stub://db/app?user=a&provider=file&path=/x");
        settings.put("seclume.datasources.default.pool.maximum-pool-size", "3");
        settings.put("seclume.datasources.orders.url", "jdbc:seclume:stub://db/orders?user=o&provider=file&path=/y");
        settings.put("seclume.field-encryption.keys.1.provider", "file");
        settings.put("seclume.field-encryption.keys.1.path", keyFile.toString());
        return settings;
    }

    @BeforeAll
    static void startTheContainer() throws Exception {
        StubDriver.INSTANCE.urls.size();
        keyFile = Files.createTempFile("seclume-helidon-cdi", ".key");
        Files.writeString(keyFile, Base64.getEncoder().encodeToString(new byte[32]));
        // System properties: a source every MicroProfile Config has, and the
        // one Helidon's container still reads after it has built its own
        // configuration on start - a config registered here would be replaced.
        settings().forEach(System::setProperty);
        ConfigProviderResolver resolver = ConfigProviderResolver.instance();
        resolver.releaseConfig(resolver.getConfig(Thread.currentThread().getContextClassLoader()));

        // What the extension will read, before the container is there to fail.
        Map<String, String> flat = SeclumeCdiExtension.flat(ConfigProvider.getConfig());
        assertTrue(flat.keySet().containsAll(List.of("seclume.field-encryption.keys.1.provider",
                "seclume.field-encryption.keys.1.path", "seclume.datasources.default.url",
                "seclume.datasources.orders.url")), flat.keySet().toString());

        container = SeContainerInitializer.newInstance().disableDiscovery().initialize();
    }

    @Test
    void theExtensionRanInTheContainerWithTheConfiguration() {
        SeclumeCdiExtension extension = container.getBeanManager().getExtension(SeclumeCdiExtension.class);
        assertEquals(Set.of("default", "orders"), extension.dataSourceNames(),
                "the data sources the extension found in the container's configuration");
    }

    @AfterAll
    static void stopTheContainer() throws Exception {
        if (container != null) {
            container.close();
        }
        settings().keySet().forEach(System::clearProperty);
        ConfigProviderResolver resolver = ConfigProviderResolver.instance();
        resolver.releaseConfig(resolver.getConfig(Thread.currentThread().getContextClassLoader()));
        Files.deleteIfExists(keyFile);
    }

    @Test
    void theBeansAreThere() throws Exception {
        DataSource primary = container.select(DataSource.class).get();
        DataSource orders = container.select(DataSource.class, NamedLiteral.of("orders")).get();
        assertEquals("default", ((SeclumePool) primary).settings().getName());
        assertEquals(3, ((SeclumePool) primary).settings().getMaximumPoolSize());
        assertEquals("orders", ((SeclumePool) orders).settings().getName());
        assertNotSame(primary, orders);
        int before = StubDriver.INSTANCE.urls.size();
        orders.getConnection().close();
        assertTrue(StubDriver.INSTANCE.urls.size() > before, "the pool connected through the stub driver");
        assertTrue(StubDriver.INSTANCE.urls.get(StubDriver.INSTANCE.urls.size() - 1).contains("/orders"));
        FieldKeys keys = container.select(FieldKeys.class).get();
        assertSame(keys, FieldKeys.installed());
        assertEquals(List.of(1), keys.keyIds());
    }

    @Test
    void theDefaultIsOneBeanUnderEveryName() {
        DataSource primary = container.select(DataSource.class).get();
        assertSame(primary, container.select(DataSource.class, NamedLiteral.of("default")).get(),
                "@Default and @Named(\"default\") are the same pool");
        assertSame(primary, container.select(SeclumePool.class).get(), "and so is the SeclumePool type");
        List<DataSource> every = container.select(DataSource.class, Any.Literal.INSTANCE).stream().toList();
        assertEquals(2, every.size(), "one bean per configured data source");
        assertEquals(Set.of("default", "orders"), every.stream()
                .map(source -> ((SeclumePool) source).settings().getName()).collect(Collectors.toSet()));
        assertTrue(container.select(DataSource.class, NamedLiteral.of("billing")).isUnsatisfied());
    }

    @Test
    void theExtensionIsFoundByTheServiceLoader() {
        long found = java.util.ServiceLoader.load(Extension.class).stream()
                .filter(provider -> provider.type() == SeclumeCdiExtension.class)
                .count();
        assertEquals(1, found, "on the class path, an application needs no code to get the beans");
    }

    /**
     * A config whose {@code getPropertyNames} leaves names out - as a config
     * built as a tree may for {@code keys.1.uri} - still gives the extension
     * every name its sources have, with the value of the highest ordinal.
     */
    @Test
    void namesComeFromTheSourcesAsWell() {
        MapSource low = new MapSource("low", 100, Map.of(
                "seclume.field-encryption.keys.1.uri", "file:/low",
                "seclume.datasources.a.url", "jdbc:seclume:stub://low",
                "other.key", "x"));
        MapSource high = new MapSource("high", 400, Map.of(
                "seclume.field-encryption.keys.1.uri", "file:/high",
                "javax.sql.DataSource.h.dataSource.url", "jdbc:seclume:stub://h"));
        Config hiding = new SourcesOnly(List.of(low, high), List.of("seclume.datasources.a.url"));
        Map<String, String> flat = SeclumeCdiExtension.flat(hiding);
        assertEquals(Map.of(
                "seclume.field-encryption.keys.1.uri", "file:/high",
                "seclume.datasources.a.url", "jdbc:seclume:stub://low",
                "javax.sql.DataSource.h.dataSource.url", "jdbc:seclume:stub://h"), flat);
        assertFalse(flat.containsKey("other.key"), "only seclume's and the data sources' keys");
    }

    /** Names only from a list, values only from the sources - the least a config can do. */
    record SourcesOnly(List<ConfigSource> sources, List<String> names) implements Config {
        @Override
        public <T> T getValue(String name, Class<T> type) {
            return getOptionalValue(name, type).orElseThrow();
        }

        @Override
        public ConfigValue getConfigValue(String name) {
            throw new UnsupportedOperationException("not needed");
        }

        @Override
        public <T> Optional<T> getOptionalValue(String name, Class<T> type) {
            throw new IllegalArgumentException("this config answers nothing by name: " + name);
        }

        @Override
        public Iterable<String> getPropertyNames() {
            return names;
        }

        @Override
        public Iterable<ConfigSource> getConfigSources() {
            return sources;
        }

        @Override
        public <T> Optional<Converter<T>> getConverter(Class<T> type) {
            return Optional.empty();
        }

        @Override
        public <T> T unwrap(Class<T> type) {
            throw new IllegalArgumentException("nothing to unwrap");
        }
    }

    @Test
    void aPasswordInTheConfigurationIsADeploymentError() {
        Map<String, String> withPassword = new HashMap<>(settings());
        withPassword.put("seclume.datasources.orders.password", "zl-cdi-canary");
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> SeclumeSettings.of(SeclumeCdiExtension.flat(new SourcesOnly(
                        List.of(new MapSource("p", 100, withPassword)), List.of()))).refusePasswords());
        assertFalse(e.getMessage().contains("zl-cdi-canary"), e.getMessage());
        assertTrue(e.getMessage().contains("seclume.datasources.orders.password"), e.getMessage());
    }
}
