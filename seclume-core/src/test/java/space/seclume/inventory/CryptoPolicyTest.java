package space.seclume.inventory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.inventory.CryptoInventory.Asset;
import space.seclume.inventory.CryptoInventory.Kind;
import space.seclume.inventory.CryptoPolicy.Finding;
import space.seclume.inventory.CryptoPolicy.Severity;

/** Every rule, met and broken, its severity, and how a policy is written down. */
class CryptoPolicyTest {

    private static final Instant T = Instant.parse("2026-10-30T12:00:00Z");

    @TempDir
    Path directory;

    private static Asset key(String algorithm, int bits) {
        return new Asset("private-key:" + algorithm + bits, Kind.PRIVATE_KEY,
                algorithm + " private key", algorithm, bits, "OpenSSL", T, T, 1, null, Map.of());
    }

    private static Asset tls(String version, String suite, String group) {
        Map<String, String> facts = new java.util.LinkedHashMap<>();
        facts.put("peer", "db:5432");
        facts.put("stack", "seclume");
        facts.put("version", version);
        facts.put("cipherSuite", suite);
        if (group != null) {
            facts.put("keyExchange", group);
        }
        return new Asset("protocol:" + version + suite + group, Kind.PROTOCOL, "TLS " + version
                + " to db", group, 0, "seclume", T, T, 1, null, Map.copyOf(facts));
    }

    private static Asset certificate(String algorithm, int bits, String signature, Instant expires) {
        return new Asset("certificate:" + algorithm + bits + signature, Kind.CERTIFICATE, "CN=db",
                algorithm, bits, "db", T, T, 1, expires, Map.of("subject", "CN=db",
                        "signatureAlgorithm", signature, "peer", "db"));
    }

    private static Asset secret(String provider) {
        return new Asset("secret:" + provider + ":1", Kind.SECRET, provider + " secret 1", null, 0,
                provider, T, T, 1, null, Map.of("provider", provider));
    }

    private static Asset dataKey(String provider) {
        return new Asset("data-key:1:1", Kind.DATA_KEY, "field encryption key 1", "AES-256-GCM-SIV",
                256, provider, T, T, 1, null, Map.of("ring", "1", "keyNumber", "1", "primary", "true"));
    }

    private static List<String> rules(List<Finding> findings, Severity severity) {
        List<String> rules = new ArrayList<>();
        for (Finding finding : findings) {
            if (finding.severity() == severity) {
                rules.add(finding.rule());
            }
        }
        return rules;
    }

    private static List<Finding> check(CryptoPolicy policy, Asset... assets) {
        return policy.check(List.of(assets), T);
    }

    @Test
    void theDefaultsPassAModernSetup() {
        List<Finding> findings = check(CryptoPolicy.of(Map.of("quantum", "off")),
                key("EC P-256", 256), key("RSA", 3072), key("Ed25519", 255),
                tls("1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768"),
                tls("1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", null),
                certificate("RSA", 2048, "SHA256withRSA", T.plusSeconds(86400 * 90)),
                secret("vault"), dataKey("kms-decrypt"));
        assertEquals(List.of(), findings);
    }

    @Test
    void rsaAndEcKeysBelowTheirMinimumFail() {
        CryptoPolicy policy = CryptoPolicy.of(Map.of("rsa.min-bits", "3072", "ec.min-bits", "384",
                "quantum", "off"));
        List<Finding> findings = check(policy, key("RSA", 2048), key("RSA", 4096),
                key("EC P-256", 256), key("EC P-384", 384),
                certificate("RSA", 2048, "SHA256withRSA", T.plusSeconds(86400 * 90)));
        assertEquals(List.of("rsa.min-bits", "ec.min-bits", "rsa.min-bits"), rules(findings, Severity.FAIL));
        assertTrue(findings.get(0).message().contains("RSA-2048, below 3072 bits"), findings.get(0).message());
        assertEquals(2, rules(check(CryptoPolicy.of(Map.of("quantum", "off")), key("RSA", 1024),
                key("EC P-224", 224)), Severity.FAIL).size());
    }

    @Test
    void anOldTlsVersionFails() {
        CryptoPolicy strict = CryptoPolicy.of(Map.of("tls.min-version", "1.3", "quantum", "off"));
        assertEquals(List.of("tls.min-version"), rules(check(strict,
                tls("1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", null)), Severity.FAIL));
        assertEquals(List.of(), check(strict, tls("1.3", "TLS_AES_128_GCM_SHA256", "X25519")));
        assertEquals(List.of("tls.min-version"), rules(check(CryptoPolicy.of(Map.of("quantum", "off")),
                tls("1.1", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", null)), Severity.FAIL));
    }

    @Test
    void aTls12SuiteWithoutForwardSecrecyFails() {
        CryptoPolicy policy = CryptoPolicy.of(Map.of("quantum", "off"));
        assertEquals(List.of("tls.forward-secrecy"), rules(check(policy,
                tls("1.2", "TLS_RSA_WITH_AES_128_GCM_SHA256", null)), Severity.FAIL));
        assertEquals(List.of(), check(policy, tls("1.2", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", null)));
        assertEquals(List.of(), check(CryptoPolicy.of(Map.of("quantum", "off", "tls.forward-secrecy",
                "false")), tls("1.2", "TLS_RSA_WITH_AES_128_GCM_SHA256", null)));
    }

    @Test
    void requiringTheHybridFailsEveryClassicalExchange() {
        CryptoPolicy policy = CryptoPolicy.of(Map.of("tls.require-hybrid", "true", "quantum", "off"));
        List<Finding> findings = check(policy, tls("1.3", "TLS_AES_256_GCM_SHA384", "X25519"),
                tls("1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", null),
                tls("1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768"));
        assertEquals(List.of("tls.require-hybrid", "tls.require-hybrid"), rules(findings, Severity.FAIL));
        assertTrue(findings.get(0).message().contains("X25519MLKEM768"));
    }

    @Test
    void aCertificateNearItsEndOrPastItFails() {
        CryptoPolicy policy = CryptoPolicy.of(Map.of("certificate.min-days", "30", "quantum", "off"));
        List<Finding> findings = check(policy,
                certificate("EC P-256", 256, "SHA256withECDSA", T.plusSeconds(86400 * 10)),
                certificate("EC P-384", 384, "SHA384withECDSA", T.minusSeconds(60)),
                certificate("EC P-521", 521, "SHA512withECDSA", T.plusSeconds(86400 * 31)));
        assertEquals(List.of("certificate.min-days", "certificate.min-days"), rules(findings, Severity.FAIL));
        assertTrue(findings.get(0).message().contains("in 10 days - fewer than 30"), findings.get(0).message());
        assertTrue(findings.get(1).message().contains("expired"), findings.get(1).message());
    }

    @Test
    void forbiddenSignaturesAndAlgorithmsFail() {
        assertEquals(List.of("signature.forbidden"), rules(check(CryptoPolicy.of(Map.of("quantum", "off")),
                certificate("RSA", 2048, "SHA1withRSA", T.plusSeconds(86400 * 90))), Severity.FAIL));
        CryptoPolicy policy = CryptoPolicy.of(Map.of("algorithm.forbidden", "AES_128, P-256",
                "quantum", "off"));
        List<Finding> findings = check(policy, tls("1.3", "TLS_AES_128_GCM_SHA256", "X25519"),
                key("EC P-256", 256), key("EC P-384", 384));
        assertEquals(List.of("algorithm.forbidden", "algorithm.forbidden"), rules(findings, Severity.FAIL));
    }

    @Test
    void secretsAndDataKeysFromForbiddenPlacesFail() {
        CryptoPolicy policy = CryptoPolicy.of(Map.of("secret.forbidden-providers", "file,env-file",
                "data-key.require-kms", "true", "quantum", "off"));
        assertEquals(List.of("secret.forbidden-providers", "secret.forbidden-providers",
                "data-key.require-kms"), rules(check(policy, secret("file"), secret("env-file"),
                secret("vault"), dataKey("file")), Severity.FAIL));
        for (String kms : List.of("kms-decrypt", "vault-transit", "shamir")) {
            assertEquals(List.of(), check(policy, dataKey(kms)), kms);
        }
        assertEquals(List.of("data-key.forbidden-providers"), rules(check(CryptoPolicy.of(Map.of(
                "data-key.forbidden-providers", "env-file", "quantum", "off")), dataKey("env-file")),
                Severity.FAIL));
    }

    @Test
    void quantumVulnerableAssetsWarnByDefaultAndFailOnRequest() {
        Asset[] assets = {tls("1.3", "TLS_AES_256_GCM_SHA384", "X25519"), key("EC P-256", 256),
                certificate("RSA", 3072, "SHA256withRSA", T.plusSeconds(86400 * 90)),
                tls("1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768"), key("ML-DSA-65", 0),
                dataKey("kms-decrypt")};
        List<Finding> warned = check(CryptoPolicy.defaults(), assets);
        assertEquals(List.of("quantum", "quantum", "quantum"), rules(warned, Severity.WARN));
        assertFalse(CryptoPolicy.fails(warned));
        List<Finding> failed = check(CryptoPolicy.of(Map.of("quantum", "fail")), assets);
        assertEquals(3, rules(failed, Severity.FAIL).size());
        assertTrue(CryptoPolicy.fails(failed));
        assertEquals(List.of(), check(CryptoPolicy.of(Map.of("quantum", "off")), assets));
    }

    @Test
    void warnOnlyTurnsARuleIntoWarnings() {
        CryptoPolicy policy = CryptoPolicy.of(Map.of("rsa.min-bits", "3072",
                "warn-only", "rsa.min-bits,quantum", "quantum", "fail"));
        List<Finding> findings = check(policy, key("RSA", 2048));
        assertEquals(List.of("rsa.min-bits", "quantum"), rules(findings, Severity.WARN));
        assertFalse(CryptoPolicy.fails(findings));
    }

    @Test
    void failuresComeBeforeWarnings() {
        List<Finding> findings = check(CryptoPolicy.defaults(), key("EC P-256", 256), key("RSA", 1024));
        assertEquals(Severity.FAIL, findings.get(0).severity());
        assertEquals(Severity.WARN, findings.get(findings.size() - 1).severity());
    }

    @Test
    void aPolicyIsRefusedForWhatItGetsWrong() {
        for (Map<String, String> wrong : List.of(Map.of("rsa.minbits", "3072"),
                Map.of("rsa.min-bits", "many"), Map.of("rsa.min-bits", "-1"),
                Map.of("tls.min-version", "1.1"), Map.of("tls.forward-secrecy", "maybe"),
                Map.of("quantum", "panic"), Map.of("warn-only", "nonsense"))) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> CryptoPolicy.of(wrong), wrong.toString());
            assertFalse(e.getMessage().isBlank());
        }
    }

    @Test
    void aPolicyFileIsReadAsProperties() throws IOException {
        Path file = Files.writeString(directory.resolve("policy.properties"), """
                # production
                rsa.min-bits = 3072
                tls.min-version=1.3
                secret.forbidden-providers=file
                quantum=fail
                """);
        CryptoPolicy policy = CryptoPolicy.load(file);
        assertEquals(List.of("rsa.min-bits", "quantum", "tls.min-version", "quantum",
                "secret.forbidden-providers"), rules(check(policy, key("RSA", 2048),
                tls("1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", null), secret("file")),
                Severity.FAIL));
    }

    @Test
    void theReportsSayWhatAndNeverMore() {
        List<Finding> findings = check(CryptoPolicy.of(Map.of("secret.forbidden-providers", "file")),
                secret("file"), key("EC P-256", 256));
        String markdown = CryptoPolicy.markdown(findings);
        assertTrue(markdown.contains("1 failing, 1 warnings."), markdown);
        assertTrue(markdown.contains("| FAIL | `secret.forbidden-providers` |"), markdown);
        String json = CryptoPolicy.json(findings);
        assertTrue(json.startsWith("{\"fails\": true, \"findings\": [{\"severity\": \"fail\""), json);
        assertTrue(CryptoPolicy.markdown(List.of()).contains("Every asset meets the policy."));
        assertEquals("{\"fails\": false, \"findings\": []}\n", CryptoPolicy.json(List.of()));
    }

    @Test
    void theSampleCbomAgainstTheDefaults() {
        List<Finding> findings = CryptoPolicy.defaults().check(CycloneDxCbomTest.everyKind(), T);
        assertFalse(CryptoPolicy.fails(findings), findings.toString());
        // EC P-256 and RSA-3072 keys, the TLS 1.2 session's ECDHE and the RSA certificate.
        assertEquals(4, rules(findings, Severity.WARN).size(), findings.toString());
    }
}
