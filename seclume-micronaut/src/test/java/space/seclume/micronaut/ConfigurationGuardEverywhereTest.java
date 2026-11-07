package space.seclume.micronaut;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.env.PropertySource;

/**
 * The password guard where a password actually comes from. In a container it
 * is an environment variable more often than a line in
 * {@code application.yml}; Micronaut reads {@code DATASOURCES_DEFAULT_PASSWORD}
 * as {@code datasources.default.password}, the same {@code String} on the
 * heap - but the guard looked at the property's spelling only, and an
 * environment variable's {@code _} never matched it. Nor did a password among
 * Hikari's data source properties.
 */
@Isolated
class ConfigurationGuardEverywhereTest {

    private static final String CANARY = "zl-guard-canary";

    /** {@code variables} as the process environment, {@code properties} as a file. */
    private static ApplicationContext start(Map<String, Object> variables, Map<String, Object> properties) {
        return ApplicationContext.builder()
                .propertySources(PropertySource.of("test-environment", variables,
                        PropertySource.PropertyConvention.ENVIRONMENT_VARIABLE))
                .properties(properties)
                .start();
    }

    private static String chain(Throwable e) {
        StringBuilder all = new StringBuilder();
        for (Throwable t = e; t != null; t = t.getCause()) {
            all.append(t.getMessage()).append(" | ");
        }
        return all.toString();
    }

    private static void assertRefused(Map<String, Object> variables, Map<String, Object> properties,
                                      String named) {
        RuntimeException e = assertThrows(RuntimeException.class,
                () -> start(variables, properties).close(), variables + " " + properties);
        assertTrue(chain(e).contains("a password stands in the configuration"), chain(e));
        assertTrue(chain(e).contains(named), "the message names " + named + ": " + chain(e));
        assertFalse(chain(e).contains(CANARY), "the message carries the password");
    }

    @Test
    void aPasswordInAnEnvironmentVariableStopsTheStart() {
        assertRefused(Map.of("DATASOURCES_DEFAULT_URL", "jdbc:seclume:postgresql://db/app?user=app",
                        "DATASOURCES_DEFAULT_PASSWORD", CANARY), Map.of(),
                "DATASOURCES_DEFAULT_PASSWORD");
        assertRefused(Map.of("SECLUME_DATASOURCES_ORDERS_PASSWORD", CANARY), Map.of(),
                "SECLUME_DATASOURCES_ORDERS_PASSWORD");
    }

    @Test
    void theUrlInAFileAndThePasswordInTheEnvironment() {
        assertRefused(Map.of("DATASOURCES_DEFAULT_PASSWORD", CANARY),
                Map.of("datasources.default.url", "jdbc:seclume:mysql://db/app?user=app"),
                "DATASOURCES_DEFAULT_PASSWORD");
    }

    @Test
    void aDataSourceWhoseNameHasADash() {
        assertRefused(Map.of("DATASOURCES_ORDERS_DB_URL", "jdbc:seclume:postgresql://db/orders?user=o",
                        "DATASOURCES_ORDERS_DB_PASSWORD", CANARY), Map.of(),
                "DATASOURCES_ORDERS_DB_PASSWORD");
        assertRefused(Map.of("DATASOURCES_ORDERS_DB_PASSWORD", CANARY),
                Map.of("datasources.orders-db.url", "jdbc:seclume:postgresql://db/orders?user=o"),
                "DATASOURCES_ORDERS_DB_PASSWORD");
    }

    @Test
    void aPasswordAmongTheDataSourceProperties() {
        for (String key : List.of("datasources.default.data-source-properties.password",
                "datasources.default.dataSourceProperties.password")) {
            assertRefused(Map.of(), Map.of("datasources.default.url",
                    "jdbc:seclume:postgresql://db/app?user=app", key, CANARY), key);
        }
        assertRefused(Map.of("DATASOURCES_DEFAULT_DATA_SOURCE_PROPERTIES_PASSWORD", CANARY),
                Map.of("datasources.default.url", "jdbc:seclume:postgresql://db/app?user=app"),
                "DATASOURCES_DEFAULT_DATA_SOURCE_PROPERTIES_PASSWORD");
    }

    @Test
    void anotherDriversPasswordIsStillNotSeclumesBusiness() {
        try (ApplicationContext context = start(Map.of("DATASOURCES_LEGACY_URL", "jdbc:h2:mem:x",
                "DATASOURCES_LEGACY_PASSWORD", "sa"), Map.of())) {
            assertTrue(context.isRunning());
        }
        try (ApplicationContext context = start(Map.of("APP_DATASOURCES_PASSWORD_HINT", "x",
                "DATASOURCES_PASSWORD", "y"), Map.of("app.name", "x"))) {
            assertTrue(context.isRunning(), "no data source's password at all");
        }
    }
}
