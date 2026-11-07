package space.seclume.quarkus.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigValue;
import org.eclipse.microprofile.config.spi.ConfigSource;
import org.eclipse.microprofile.config.spi.Converter;
import org.junit.jupiter.api.Test;

import io.quarkus.runtime.configuration.ConfigurationException;

import space.seclume.quarkus.SeclumePasswordGuard;

/**
 * Which names the password check takes for a seclume datasource's password -
 * as properties and as the environment variables Quarkus reads as them.
 */
class PasswordGuardNamesTest {

    /** A config of these names and values, nothing more. */
    record MapConfig(Map<String, String> values) implements Config {
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
            return Optional.ofNullable(values.get(name)).map(type::cast);
        }

        @Override
        public Iterable<String> getPropertyNames() {
            return values.keySet();
        }

        @Override
        public Iterable<ConfigSource> getConfigSources() {
            return List.of();
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

    private static List<String> refused(String... namesAndValues) {
        Map<String, String> values = new LinkedHashMap<>();
        for (int i = 0; i + 1 < namesAndValues.length; i += 2) {
            values.put(namesAndValues[i], namesAndValues[i + 1]);
        }
        return SeclumePasswordGuard.refused(new MapConfig(values));
    }

    @Test
    void theDefaultDatasource() {
        assertEquals(List.of("quarkus.datasource.password"), refused(
                "quarkus.datasource.db-kind", "seclume-postgresql",
                "quarkus.datasource.password", "x"));
        assertEquals(List.of("QUARKUS_DATASOURCE_PASSWORD"), refused(
                "quarkus.datasource.db-kind", "seclume-mysql",
                "QUARKUS_DATASOURCE_PASSWORD", "x"));
    }

    @Test
    void aNamedDatasource() {
        assertEquals(List.of("QUARKUS_DATASOURCE_USERS_PASSWORD"), refused(
                "quarkus.datasource.users.db-kind", "seclume-postgresql",
                "QUARKUS_DATASOURCE_USERS_PASSWORD", "x"));
        assertEquals(List.of("QUARKUS_DATASOURCE__USERS__PASSWORD"), refused(
                "quarkus.datasource.\"users\".db-kind", "seclume-postgresql",
                "QUARKUS_DATASOURCE__USERS__PASSWORD", "x"));
        assertEquals(List.of("QUARKUS_DATASOURCE_ORDERS_DB_PASSWORD"), refused(
                "quarkus.datasource.orders-db.db-kind", "seclume-sqlserver",
                "QUARKUS_DATASOURCE_ORDERS_DB_PASSWORD", "x"));
        assertEquals(List.of("quarkus.datasource.\"orders\".password"), refused(
                "quarkus.datasource.\"orders\".db-kind", "seclume-oracle",
                "quarkus.datasource.\"orders\".password", "x"));
    }

    @Test
    void anotherDriversPasswordIsNotSeclumesBusiness() {
        assertEquals(List.of(), refused(
                "quarkus.datasource.db-kind", "postgresql",
                "quarkus.datasource.password", "x",
                "QUARKUS_DATASOURCE_PASSWORD", "x"));
        assertEquals(List.of(), refused(
                "quarkus.datasource.db-kind", "seclume-postgresql",
                "quarkus.datasource.legacy.db-kind", "h2",
                "QUARKUS_DATASOURCE_LEGACY_PASSWORD", "sa",
                "QUARKUS_DATASOURCE_PASSWORD_FILE", "/run/secrets/db",
                "quarkus.datasource.jdbc.url", "jdbc:seclume:postgresql://db/app?user=app"));
    }

    @Test
    void theMessageNamesThePropertyNeverTheValue() {
        Map<String, String> values = Map.of("quarkus.datasource.db-kind", "seclume-postgresql",
                "QUARKUS_DATASOURCE_PASSWORD", "zl-quarkus-canary");
        ConfigurationException e = assertThrows(ConfigurationException.class,
                () -> SeclumePasswordGuard.refuse(new MapConfig(values)));
        assertTrue(e.getMessage().contains("QUARKUS_DATASOURCE_PASSWORD"), e.getMessage());
        assertFalse(e.getMessage().contains("zl-quarkus-canary"), e.getMessage());
    }
}
