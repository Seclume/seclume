package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Each weakening switch was reasonable somewhere and said nowhere: a data
 * source left on the driver's TLS default, the secret guard off, a lowered
 * SCRAM floor. One line at start names them all.
 */
class WeakenedSettingsTest {

    @Test
    void everyWeakeningIsNamed() {
        Map<String, String> settings = Map.of("seclume.secret-guard", "off",
                "seclume.crypto-policy.enabled", "false");
        Map<String, String> properties = Map.of("seclume.scram.minIterations", "1000",
                "seclume.allowUnverifiedSecretSources", "true", "seclume.crac.holdExpiry", "release");
        List<String> weakened = SeclumeWeakenedSettingsAutoConfiguration.weakened(
                settings::get, properties::get, new java.util.TreeMap<>(Map.of(
                        "orders", "jdbc:seclume:postgresql://db/orders?tls=prefer",
                        "reports", "jdbc:seclume:mysql://db/reports",
                        "staging", "jdbc:seclume:sqlserver://db/staging?trustServerCertificate=true",
                        "billing", "jdbc:seclume:sqlserver://db/billing?tls=verify-full")));
        // reports names no tls: verify-full, the default - nothing to say.
        assertEquals(List.of("datasource orders: tls not verify-full (prefer)",
                "datasource staging: trustServerCertificate=true",
                "seclume.secret-guard=off", "seclume.crypto-policy.enabled=false",
                "seclume.crac.holdExpiry=release",
                "seclume.allowUnverifiedSecretSources=true", "seclume.scram.minIterations=1000"),
                weakened);
    }

    /**
     * The same list in {@code /actuator/seclume}: a context that starts with
     * the secret guard off shows it there, under weakenedSettings.
     */
    @Test
    void theEndpointNamesThemToo() {
        try (org.springframework.context.annotation.AnnotationConfigApplicationContext context =
                     new org.springframework.context.annotation.AnnotationConfigApplicationContext()) {
            context.getEnvironment().getPropertySources().addFirst(
                    new org.springframework.core.env.MapPropertySource("test",
                            Map.of("seclume.secret-guard", "off")));
            context.register(SeclumeWeakenedSettingsAutoConfiguration.class);
            context.refresh();
            Object shown = new SeclumeEndpoint(List.of()).report().get("weakenedSettings");
            assertEquals(List.of("seclume.secret-guard=off"), shown);
        }
    }

    @Test
    void theDefaultsAreNothingToSay() {
        assertTrue(SeclumeWeakenedSettingsAutoConfiguration.weakened(key -> null, key -> null,
                Map.of("orders", "jdbc:seclume:postgresql://db/orders?TLS=Verify-Full")).isEmpty());
    }
}
