package space.seclume.inventory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import space.seclume.inventory.CryptoInventory.Asset;
import space.seclume.inventory.CryptoInventory.Kind;

/**
 * The CBOM's content, asset by asset, with the quantum security levels each
 * algorithm gets; and a sample of every kind written to
 * {@code target/cbom-sample.json}, which CI checks against CycloneDX's own
 * JSON schema ({@code validate_cbom.py}).
 */
class CycloneDxCbomTest {

    private static final Instant T = Instant.parse("2026-10-30T12:00:00Z");

    static List<Asset> everyKind() {
        return List.of(
                new Asset("secret:vault:1", Kind.SECRET, "vault secret 1", null, 0,
                        "VaultSecretProvider[https://vault:8200/v1/database/creds/app]", T, T, 7,
                        T.plusSeconds(3600), Map.of("provider", "vault", "held",
                                "locked native memory, wiped after use")),
                new Asset("secret:gcp-metadata:1", Kind.SECRET, "gcp-metadata secret 1", null, 0,
                        "gcp-metadata", T, T, 2, null, Map.of("provider", "gcp-metadata")),
                new Asset("data-key:1:2", Kind.DATA_KEY, "field encryption key 2",
                        "AES-256-GCM-SIV", 256, "vault-transit", T, T, 1, null,
                        Map.of("primary", "true")),
                new Asset("private-key:1", Kind.PRIVATE_KEY, "EC P-256 private key 1",
                        "EC P-256", 256, "OpenSSL", T, T, 1, null, Map.of()),
                new Asset("private-key:2", Kind.PRIVATE_KEY, "RSA private key 2", "RSA", 3072,
                        "AWS KMS key alias/tls in eu-central-1", T, T, 1, null, Map.of()),
                new Asset("protocol:tls:db:seclume", Kind.PROTOCOL, "TLS 1.3 to db",
                        "X25519MLKEM768", 0, "seclume", T, T, 40, null, Map.of("peer", "db",
                                "stack", "seclume", "version", "1.3", "cipherSuite",
                                "TLS_AES_256_GCM_SHA384", "keyExchange", "X25519MLKEM768")),
                new Asset("protocol:tls:legacy:JSSE", Kind.PROTOCOL, "TLS 1.2 to legacy", null, 0,
                        "JSSE", T, T, 3, null, Map.of("peer", "legacy:1433", "stack", "JSSE",
                                "version", "1.2", "cipherSuite",
                                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")),
                new Asset("certificate:CN=CA:1f", Kind.CERTIFICATE, "CN=db", "RSA", 2048, "db",
                        T, T, 40, T.plusSeconds(86400 * 90), Map.of("subject", "CN=db \"main\"",
                                "issuer", "CN=CA", "notBefore", T.toString(),
                                "signatureAlgorithm", "SHA256withRSA", "serialNumber", "1f",
                                "peer", "db")));
    }

    private static String component(String json, String ref) {
        Matcher m = Pattern.compile("\\{\"type\": \"cryptographic-asset\", \"bom-ref\": \""
                + Pattern.quote(ref) + "\".*", Pattern.MULTILINE).matcher(json);
        assertTrue(m.find(), "no component " + ref + " in\n" + json);
        return m.group();
    }

    @Test
    void everyKindAndItsQuantumLevel() throws Exception {
        String json = CycloneDxCbom.write("orders \"service\"", everyKind(), T);
        Path target = Path.of("target");
        Files.createDirectories(target);
        Files.writeString(target.resolve("cbom-sample.json"), json);

        assertTrue(json.startsWith("{\n  \"bomFormat\": \"CycloneDX\",\n  \"specVersion\": \"1.6\""));
        assertTrue(json.contains("\"name\": \"orders \\\"service\\\"\""), "escaping");
        assertTrue(component(json, "algorithm:AES-256-GCM-SIV")
                .contains("\"nistQuantumSecurityLevel\": 5"));
        assertTrue(component(json, "algorithm:X25519MLKEM768")
                .contains("\"primitive\": \"kem\""));
        assertTrue(component(json, "algorithm:X25519MLKEM768")
                .contains("\"nistQuantumSecurityLevel\": 3"));
        assertTrue(component(json, "algorithm:ECDHE").contains("\"nistQuantumSecurityLevel\": 0"));
        assertTrue(component(json, "algorithm:RSA-3072").contains("\"classicalSecurityLevel\": 128"));
        assertTrue(component(json, "algorithm:RSA-2048").contains("\"classicalSecurityLevel\": 112"));
        assertTrue(component(json, "algorithm:ECDSA P-256").contains("\"nistQuantumSecurityLevel\": 0"));
        assertTrue(component(json, "algorithm:AES-128-GCM").contains("\"mode\": \"gcm\""));
        assertTrue(component(json, "secret:gcp-metadata:1").contains("\"type\": \"token\""));
        assertTrue(component(json, "secret:vault:1").contains("\"type\": \"credential\""));
        assertTrue(component(json, "secret:vault:1").contains("\"expirationDate\": \"2026-10-30T13:00:00Z\""));
        assertTrue(component(json, "private-key:2").contains("\"mechanism\": \"KMS\""));
        assertTrue(component(json, "private-key:1").contains("\"mechanism\": \"Software\""));
        assertTrue(component(json, "certificate:CN=CA:1f")
                .contains("\"signatureAlgorithmRef\": \"algorithm:SHA256withRSA\""));
        assertTrue(json.contains("{\"ref\": \"protocol:tls:db:seclume\", \"dependsOn\": "
                + "[\"certificate:CN=CA:1f\"]}"));
        // RSA-3072 and EC P-256 keys, the RSA certificate, the TLS 1.2 ECDHE session;
        // not the hybrid session, not the AES key.
        assertTrue(json.contains("{\"name\": \"seclume:quantum-vulnerable\", \"value\": \"4\"}"),
                json);
    }

    @Test
    void anEmptyInventoryIsAValidEmptyBom() {
        String json = CycloneDxCbom.write(null, List.of(), T);
        assertTrue(json.contains("\"components\": [\n\n  ]"), json);
        assertFalse(json.contains("dependencies"));
        assertTrue(json.contains("\"name\": \"application\""));
    }

    @Test
    void stringsAreEscaped() {
        assertEquals("\"a\\\"b\\\\c\\n\\u0001\"", CycloneDxCbom.string("a\"b\\c\n\u0001"));
    }
}
