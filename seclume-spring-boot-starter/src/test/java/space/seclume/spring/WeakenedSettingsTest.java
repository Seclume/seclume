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
                "seclume.allowUnverifiedSecretSources", "true");
        List<String> weakened = SeclumeWeakenedSettingsAutoConfiguration.weakened(
                settings::get, properties::get, new java.util.TreeMap<>(Map.of(
                        "orders", "jdbc:seclume:postgresql://db/orders?tls=prefer",
                        "reports", "jdbc:seclume:mysql://db/reports",
                        "billing", "jdbc:seclume:sqlserver://db/billing?tls=verify-full")));
        assertEquals(List.of("datasource orders: tls not verify-full (prefer)",
                "datasource reports: tls not verify-full (the driver's default)",
                "seclume.secret-guard=off", "seclume.crypto-policy.enabled=false",
                "seclume.allowUnverifiedSecretSources=true", "seclume.scram.minIterations=1000"),
                weakened);
    }

    @Test
    void theDefaultsAreNothingToSay() {
        assertTrue(SeclumeWeakenedSettingsAutoConfiguration.weakened(key -> null, key -> null,
                Map.of("orders", "jdbc:seclume:postgresql://db/orders?TLS=Verify-Full")).isEmpty());
    }
}
