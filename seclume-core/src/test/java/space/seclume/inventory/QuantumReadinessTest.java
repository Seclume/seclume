package space.seclume.inventory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.inventory.CryptoInventory.Asset;
import space.seclume.inventory.CryptoInventory.Kind;
import space.seclume.inventory.QuantumReadiness.Item;
import space.seclume.inventory.QuantumReadiness.Priority;
import space.seclume.inventory.QuantumReadiness.Report;

/** What breaks, in which order, and what to put in its place. */
class QuantumReadinessTest {

    private static final Instant T = Instant.parse("2026-10-30T12:00:00Z");

    private static Asset tls(String version, String suite, String group, String stack) {
        Map<String, String> facts = new java.util.LinkedHashMap<>();
        facts.put("peer", "db");
        facts.put("stack", stack);
        facts.put("version", version);
        facts.put("cipherSuite", suite);
        if (group != null) {
            facts.put("keyExchange", group);
        }
        return new Asset("protocol:" + suite + group + stack, Kind.PROTOCOL, "TLS " + version + " to db",
                group, 0, stack, T, T, 1, null, Map.copyOf(facts));
    }

    @Test
    void theSampleInTheOrderOfTheThreat() {
        Report report = QuantumReadiness.assess(CycloneDxCbomTest.everyKind());
        // assessed: the data key, two private keys, two sessions, one certificate.
        assertEquals(6, report.assessed());
        List<Priority> order = report.items().stream().map(Item::priority).toList();
        assertEquals(List.of(Priority.HIGH, Priority.MEDIUM, Priority.MEDIUM, Priority.MEDIUM,
                Priority.LOW), order, report.items().toString());
        Item first = report.items().get(0);
        assertEquals("protocol:tls:legacy:JSSE", first.ref());
        assertEquals("ECDHE", first.today());
        assertTrue(first.threat().contains("harvest now, decrypt later"));
        assertTrue(first.replacement().contains("X25519MLKEM768"));
        assertTrue(first.how().contains("TLS 1.3"), first.how());
        // ready: the data key and the hybrid session; the TLS 1.2 one has only a LOW item
        // besides its HIGH one, the keys and the certificate are not.
        assertEquals(2, report.ready());
        assertEquals(33, report.percent());
    }

    @Test
    void aJsseSessionOnTls13IsToldToUseSeclumesStack() {
        Report report = QuantumReadiness.assess(List.of(
                tls("1.3", "TLS_AES_256_GCM_SHA384", "X25519", "JSSE")));
        assertTrue(report.items().get(0).how().startsWith("tlsStack=seclume"), report.items().toString());
        Report own = QuantumReadiness.assess(List.of(
                tls("1.3", "TLS_AES_256_GCM_SHA384", "secp256r1", "seclume")));
        assertTrue(own.items().get(0).how().contains("enable X25519MLKEM768 on the server"));
    }

    @Test
    void theHybridIsReadyAndAes128IsOnlyLow() {
        Report report = QuantumReadiness.assess(List.of(
                tls("1.3", "TLS_AES_128_GCM_SHA256", "X25519MLKEM768", "seclume")));
        assertEquals(1, report.assessed());
        assertEquals(1, report.ready());
        assertEquals(List.of(Priority.LOW), report.items().stream().map(Item::priority).toList());
        assertEquals(100, report.percent());
    }

    @Test
    void secretsAreNotAssessedAndNothingIsAllReady() {
        Report report = QuantumReadiness.assess(List.of(new Asset("secret:file:1", Kind.SECRET,
                "file secret 1", null, 0, "file", T, T, 1, null, Map.of("provider", "file"))));
        assertEquals(0, report.assessed());
        assertEquals(100, report.percent());
        assertTrue(report.markdown().contains("Nothing here relies on what a quantum computer breaks."));
    }

    @Test
    void whatIsVulnerable() {
        assertEquals("X25519", QuantumReadiness.vulnerable(tls("1.3", "TLS_AES_256_GCM_SHA384",
                "X25519", "seclume")));
        assertNull(QuantumReadiness.vulnerable(tls("1.3", "TLS_AES_256_GCM_SHA384",
                "X25519MLKEM768", "seclume")));
        assertEquals("ECDHE", QuantumReadiness.vulnerable(tls("1.2",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", null, "JSSE")));
        // A key exchange nobody reported is not counted as broken - nor as safe in a report.
        assertNull(QuantumReadiness.vulnerable(tls("1.2", "", null, "JSSE")));
        Asset mlDsa = new Asset("private-key:9", Kind.PRIVATE_KEY, "ML-DSA-65 key", "ML-DSA-65", 0,
                "OpenSSL", T, T, 1, null, Map.of());
        assertNull(QuantumReadiness.vulnerable(mlDsa));
        Asset ed = new Asset("private-key:8", Kind.PRIVATE_KEY, "Ed25519 key", "Ed25519", 255,
                "OpenSSL", T, T, 1, null, Map.of());
        assertEquals("Ed25519", QuantumReadiness.vulnerable(ed));
    }

    @Test
    void markdownAndJson() {
        Report report = QuantumReadiness.assess(CycloneDxCbomTest.everyKind());
        String markdown = report.markdown();
        assertTrue(markdown.startsWith("## Post-quantum readiness\n\n2 of 6 assets ready (33 %)."), markdown);
        assertTrue(markdown.contains("| high | TLS 1.2 to legacy | ECDHE |"), markdown);
        String json = report.json();
        assertTrue(json.startsWith("{\"assessed\": 6, \"ready\": 2, \"percent\": 33, \"items\": [{\"priority\": \"high\""),
                json);
    }
}
