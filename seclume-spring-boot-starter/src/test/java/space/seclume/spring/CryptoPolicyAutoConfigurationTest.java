package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;

import space.seclume.inventory.CryptoInventory;
import space.seclume.inventory.CryptoPolicy;

/**
 * The crypto policy from {@code application.properties}: its rules bound, the
 * start-up check that logs or stops, the health contributor that goes down,
 * and {@code /actuator/quantum}.
 *
 * <p>Isolated: the inventory is the process's. The session recorded here - a
 * TLS 1.2 suite without forward secrecy, to a peer only this test uses - is
 * what the policy is made to fail on.
 */
@Isolated
class CryptoPolicyAutoConfigurationTest {

    private static final String PEER = "crypto-policy-test.invalid:5432";

    private static AnnotationConfigApplicationContext context(Map<String, Object> properties) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("test",
                new LinkedHashMap<>(properties)));
        context.register(SeclumeCryptoPolicyAutoConfiguration.class);
        context.refresh();
        return context;
    }

    /** Every rule a warning, so that whatever else the process holds cannot fail it. */
    private static Map<String, Object> lenient() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("seclume.crypto-policy.rules.warn-only", String.join(",",
                "rsa.min-bits", "ec.min-bits", "tls.min-version", "tls.forward-secrecy",
                "tls.require-hybrid", "certificate.min-days", "signature.forbidden",
                "algorithm.forbidden", "secret.forbidden-providers", "data-key.require-kms",
                "data-key.forbidden-providers", "quantum"));
        return properties;
    }

    private static void recordAWeakSession() {
        CryptoInventory.tls(PEER, "JSSE", "TLSv1.2 / TLS_RSA_WITH_AES_128_GCM_SHA256", null);
    }

    @Test
    void theRulesAreBoundFromTheProperties() {
        try (AnnotationConfigApplicationContext context = context(Map.of(
                "seclume.crypto-policy.rules.rsa.min-bits", "4096",
                "seclume.crypto-policy.rules.tls.min-version", "1.3"))) {
            CryptoPolicy policy = context.getBean(CryptoPolicy.class);
            recordAWeakSession();
            List<String> rules = policy.check(CryptoInventory.snapshot(), java.time.Instant.now())
                    .stream().filter(f -> f.asset().contains(PEER)).map(CryptoPolicy.Finding::rule).toList();
            assertTrue(rules.contains("tls.min-version"), rules.toString());
            assertTrue(rules.contains("tls.forward-secrecy"), rules.toString());
        }
    }

    @Test
    void aWrongRuleStopsTheContext() {
        assertThrows(Exception.class, () -> context(Map.of(
                "seclume.crypto-policy.rules.rsa.minbits", "4096")).close());
        assertThrows(Exception.class, () -> context(Map.of(
                "seclume.crypto-policy.on-start", "sometimes")).close());
    }

    @Test
    void onStartFailStopsTheApplicationOnAFailingFinding() throws Exception {
        recordAWeakSession();
        try (AnnotationConfigApplicationContext context = context(Map.of(
                "seclume.crypto-policy.on-start", "fail"))) {
            ApplicationRunner check = context.getBean("seclumeCryptoPolicyCheck", ApplicationRunner.class);
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> check.run(new DefaultApplicationArguments()));
            assertTrue(e.getMessage().contains("the crypto policy is not met"), e.getMessage());
        }
        Map<String, Object> warnOnly = lenient();
        warnOnly.put("seclume.crypto-policy.on-start", "fail");
        try (AnnotationConfigApplicationContext context = context(warnOnly)) {
            context.getBean("seclumeCryptoPolicyCheck", ApplicationRunner.class)
                    .run(new DefaultApplicationArguments());
        }
        Map<String, Object> warn = new LinkedHashMap<>(Map.of("seclume.crypto-policy.on-start", "warn"));
        try (AnnotationConfigApplicationContext context = context(warn)) {
            context.getBean("seclumeCryptoPolicyCheck", ApplicationRunner.class)
                    .run(new DefaultApplicationArguments());
        }
    }

    @Test
    void theHealthGoesDownWhileThePolicyFails() {
        recordAWeakSession();
        try (AnnotationConfigApplicationContext context = context(Map.of())) {
            Health health = context.getBean(SeclumeCryptoPolicyHealth.class).health();
            assertEquals(Status.DOWN, health.getStatus());
            assertTrue(health.getDetails().get("findings").toString().contains("tls.forward-secrecy"),
                    health.getDetails().toString());
        }
        try (AnnotationConfigApplicationContext context = context(lenient())) {
            Health health = context.getBean(SeclumeCryptoPolicyHealth.class).health();
            assertEquals(Status.UP, health.getStatus());
        }
    }

    @Test
    void theQuantumEndpointIsThere() {
        recordAWeakSession();
        try (AnnotationConfigApplicationContext context = context(Map.of())) {
            SeclumeQuantumEndpoint endpoint = context.getBean(SeclumeQuantumEndpoint.class);
            assertEquals("quantum", SeclumeQuantumEndpoint.class.getAnnotation(Endpoint.class).id());
            String json = endpoint.quantum();
            assertTrue(json.startsWith("{\"assessed\": "), json);
            assertTrue(json.contains(PEER), json);
        }
    }

    @Test
    void enabledFalseTurnsItOff() {
        try (AnnotationConfigApplicationContext context = context(Map.of(
                "seclume.crypto-policy.enabled", "false"))) {
            assertFalse(context.containsBean("seclumeCryptoPolicyCheck"));
            assertEquals(0, context.getBeanNamesForType(CryptoPolicy.class).length);
        }
    }
}
