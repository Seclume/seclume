package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.field.FieldKeys;
import space.seclume.inventory.CryptoInventory;
import space.seclume.inventory.CryptoInventory.Asset;
import space.seclume.inventory.CryptoInventory.Kind;
import space.seclume.inventory.CycloneDxCbom;
import space.seclume.tls.TestCertificates;

/**
 * The inventory as an application builds it, without being told anything: a
 * field encryption ring whose data key Vault transit opens over TLS, with the
 * Vault token from a file. Afterwards the inventory holds both secrets read,
 * the TLS session to Vault and Vault's certificate, and the ring's key - and
 * the CBOM made of it, which CI checks against CycloneDX's schema, holds none
 * of the token, the ciphertext's plaintext or the key.
 *
 * <p>Isolated: the inventory is the process's.
 */
@Timeout(120)
@Isolated
class InventoryEndToEndTest {

    private static final String TOKEN = "hvs.zlInventoryToken3b9e1c";

    private static TestCertificates certificates;
    private static SSLContext context;

    @TempDir
    static Path directory;

    @BeforeAll
    static void anAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        context = FakeVaultServer.context(certificates);
    }

    @AfterAll
    static void removeIt() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    @Test
    void anApplicationsCryptographyIsInventoriedAndNothingSecretIsInIt() throws Exception {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i * 37 + 11);
        }
        String keyBase64 = Base64.getEncoder().encodeToString(key);
        Path token = Files.writeString(directory.resolve("token"), TOKEN);
        FakeVaultServer.Script script = new FakeVaultServer.Script().on("POST",
                "/v1/transit/decrypt/field-data", 200,
                "{\"data\":{\"plaintext\":\"" + keyBase64 + "\"}}");
        try (FakeVaultServer vault = new FakeVaultServer(context, script)) {
            Map<String, String> settings = new LinkedHashMap<>();
            settings.put("provider", "vault-transit");
            settings.put("address", vault.address());
            settings.put("verify", "false");
            settings.put("key-name", "field-data");
            settings.put("ciphertext", "vault:v1:AAAA");
            settings.put("token-provider", "file");
            settings.put("token-path", token.toString());
            try (FieldKeys keys = FieldKeys.builder().key(1, SecretProviders.of(settings))
                    .build()) {
                List<Asset> assets = CryptoInventory.snapshot();
                List<String> providers = assets.stream().filter(a -> a.kind() == Kind.SECRET)
                        .map(a -> a.facts().get("provider")).toList();
                assertTrue(providers.contains("file"), providers.toString());
                assertTrue(providers.contains("vault-transit"), providers.toString());
                assertTrue(assets.stream().anyMatch(a -> a.kind() == Kind.DATA_KEY
                        && "vault-transit".equals(a.source())), assets.toString());
                Asset session = assets.stream().filter(a -> a.kind() == Kind.PROTOCOL
                        && a.facts().get("peer").startsWith("127.0.0.1")).findFirst()
                        .orElseThrow(() -> new AssertionError("no TLS session to Vault: "
                                + assets));
                assertTrue(session.facts().get("version").startsWith("1."), session.toString());
                assertTrue(assets.stream().anyMatch(a -> a.kind() == Kind.CERTIFICATE
                        && a.name().contains("vault")), "no certificate of Vault: " + assets);

                String cbom = CycloneDxCbom.write("inventory-end-to-end");
                Files.createDirectories(Path.of("target"));
                Files.writeString(Path.of("target", "cbom-end-to-end.json"), cbom);
                assertFalse(cbom.contains(TOKEN), "the Vault token is in the CBOM");
                assertFalse(cbom.contains(keyBase64), "the data key is in the CBOM");
                assertFalse(cbom.contains("zlInventory"));
                assertTrue(cbom.contains("\"algorithm:AES-256-GCM-SIV\""));
                assertEquals(1, keys.keyIds().size());
            }
        }
    }
}
