package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.FieldKeys;
import space.seclume.tls.TestCertificates;

/**
 * {@code provider=vault-transit} against {@link FakeVaultServer}: what is
 * asked of Vault, what is made of its answer, and every answer that is not
 * one. The real Vault and OpenBao are {@code LocalVaultTransitFieldKeyTest}'s.
 */
@Timeout(120)
class VaultTransitSecretProviderTest {

    private static final String CIPHERTEXT = "vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w==";

    private static TestCertificates certificates;
    private static SSLContext context;

    @TempDir
    static Path directory;
    private static Path token;

    @BeforeAll
    static void anAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        context = FakeVaultServer.context(certificates);
        token = Files.writeString(directory.resolve("token"), "hvs.field-reader\n");
    }

    @AfterAll
    static void removeIt() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    private static Map<String, String> settings(FakeVaultServer vault) {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "vault-transit");
        settings.put("address", vault.address());
        settings.put("verify", "false");
        settings.put("key-name", "field-data");
        settings.put("ciphertext", CIPHERTEXT);
        settings.put("token-provider", "file");
        settings.put("token-path", token.toString());
        return settings;
    }

    private static String answer(byte[] plaintext) {
        return "{\"request_id\":\"r\",\"data\":{\"plaintext\":\""
                + Base64.getEncoder().encodeToString(plaintext) + "\"}}";
    }

    private static byte[] read(SecretProvider provider) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            int length = provider.writeSecret(target);
            return target.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
        }
    }

    @Test
    void theCiphertextGoesToDecryptAndThePlaintextComesBackDecoded() throws Exception {
        byte[] key = new byte[32];
        new java.util.Random(1).nextBytes(key);
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/transit/decrypt/field-data", 200, answer(key));
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             SecretProvider provider = SecretProviders.of(settings(vault))) {
            assertArrayEquals(key, read(provider));
            FakeVaultServer.Request request = vault.requests().get(0);
            assertEquals("hvs.field-reader", request.header("X-Vault-Token"));
            assertEquals("{\"ciphertext\":\"" + CIPHERTEXT + "\"}", request.body());
            assertEquals("application/json", request.header("Content-Type"));
        }
    }

    @Test
    void aDataKeyFromTransitKeysAFieldRing() throws Exception {
        byte[] key = new byte[32];
        new java.util.Random(2).nextBytes(key);
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/transit/decrypt/field-data", 200, answer(key));
        try (FakeVaultServer vault = new FakeVaultServer(context, script)) {
            byte[] stored;
            try (FieldKeys keys = FieldKeys.builder()
                    .key(1, SecretProviders.of(settings(vault))).build()) {
                stored = keys.column("t.c", EncryptedColumn.Mode.RANDOMIZED)
                        .encrypt(MemorySegment.ofArray("value".getBytes(StandardCharsets.UTF_8)));
            }
            // A second start reads the same key from Vault and reads the value.
            try (FieldKeys keys = FieldKeys.builder()
                    .key(1, SecretProviders.of(settings(vault))).build();
                 SecretScope out = SecretScope.allocate(16)) {
                out.length(keys.column("t.c", EncryptedColumn.Mode.RANDOMIZED)
                        .decrypt(stored, out.segment()));
                assertEquals("value", new String(out.secret().toArray(ValueLayout.JAVA_BYTE),
                        StandardCharsets.UTF_8));
            }
            assertEquals(2, vault.requests().size(), "once per ring, not per value");
        }
    }

    /** One line, as the JDBC URL and the starter take it: the ciphertext's ':' and '=' survive. */
    @Test
    void oneLineAsAUri() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/transit/decrypt/field-data", 200, answer(new byte[] {9, 8, 7}));
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             SecretProvider provider = SecretProviders.fromUri("vault-transit?address="
                     + vault.address() + "&verify=false&key-name=field-data&ciphertext="
                     + CIPHERTEXT + "&token-provider=file&token-path=" + token)) {
            assertArrayEquals(new byte[] {9, 8, 7}, read(provider));
            assertEquals("{\"ciphertext\":\"" + CIPHERTEXT + "\"}", vault.requests().get(0).body());
        }
    }

    @Test
    void mountNamespaceAndContextGoWhereTransitWantsThem() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/kms/decrypt/field-data", 200, answer(new byte[] {1, 2, 3}));
        try (FakeVaultServer vault = new FakeVaultServer(context, script)) {
            Map<String, String> settings = settings(vault);
            settings.put("transit-mount", "/kms/");
            settings.put("namespace", "team-a");
            settings.put("context", "dGVuYW50LTc=");
            try (SecretProvider provider = SecretProviders.of(settings)) {
                assertArrayEquals(new byte[] {1, 2, 3}, read(provider));
            }
            FakeVaultServer.Request request = vault.requests().get(0);
            assertEquals("team-a", request.header("X-Vault-Namespace"));
            assertEquals("{\"ciphertext\":\"" + CIPHERTEXT + "\",\"context\":\"dGVuYW50LTc=\"}",
                    request.body());
        }
    }

    @Test
    void vaultsRefusalsAreSaidAndNothingIsWritten() throws Exception {
        for (int status : new int[] {400, 403, 500}) {
            FakeVaultServer.Script script = new FakeVaultServer.Script()
                    .on("POST", "/v1/transit/decrypt/field-data", status,
                            "{\"errors\":[\"permission denied\"]}");
            try (FakeVaultServer vault = new FakeVaultServer(context, script);
                 SecretProvider provider = SecretProviders.of(settings(vault));
                 Arena arena = Arena.ofConfined()) {
                MemorySegment target = arena.allocate(provider.maxSecretLength());
                SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                        () -> provider.writeSecret(target));
                assertTrue(e.getMessage().contains(String.valueOf(status)), e.getMessage());
                if (status == 403) {
                    assertTrue(e.getMessage().contains("update on transit/decrypt/field-data"),
                            e.getMessage());
                }
            }
        }
    }

    @Test
    void answersThatAreNotAPlaintextAreRefused() throws Exception {
        for (String body : new String[] {"{}", "{\"data\":{}}", "{\"data\":{\"plaintext\":7}}",
                "{\"data\":{\"plaintext\":\"not*base64\"}}", "not json at all", "{\"data\":"}) {
            FakeVaultServer.Script script = new FakeVaultServer.Script()
                    .on("POST", "/v1/transit/decrypt/field-data", 200, body);
            try (FakeVaultServer vault = new FakeVaultServer(context, script);
                 SecretProvider provider = SecretProviders.of(settings(vault));
                 Arena arena = Arena.ofConfined()) {
                MemorySegment target = arena.allocate(provider.maxSecretLength());
                assertThrows(SecretUnavailableException.class, () -> provider.writeSecret(target),
                        body);
            }
        }
    }

    @Test
    void aPlaintextLargerThanAllowedIsRefused() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/transit/decrypt/field-data", 200, answer(new byte[600]));
        try (FakeVaultServer vault = new FakeVaultServer(context, script)) {
            Map<String, String> settings = settings(vault);
            settings.put("max-length", "64");
            try (SecretProvider provider = SecretProviders.of(settings);
                 Arena arena = Arena.ofConfined()) {
                MemorySegment target = arena.allocate(provider.maxSecretLength());
                SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                        () -> provider.writeSecret(target));
                assertTrue(e.getMessage().contains("max-length"), e.getMessage());
            }
        }
    }

    @Test
    void theSettingsAreCheckedBeforeAnythingIsAsked() {
        Map<String, String> base = new LinkedHashMap<>();
        base.put("provider", "vault-transit");
        base.put("address", "https://127.0.0.1:1");
        base.put("key-name", "field-data");
        base.put("ciphertext", CIPHERTEXT);
        base.put("token-provider", "file");
        base.put("token-path", token.toString());

        Map<String, String> http = new LinkedHashMap<>(base);
        http.put("address", "http://127.0.0.1:8200");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(http))
                .getMessage().contains("https"));
        for (String bad : new String[] {"plain-base64==", "vault:v1:", "vault:vx:AAAA",
                "vault:v1:AA\"}AA"}) {
            Map<String, String> settings = new LinkedHashMap<>(base);
            settings.put("ciphertext", bad);
            assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(settings), bad);
        }
        Map<String, String> path = new LinkedHashMap<>(base);
        path.put("key-name", "../sys");
        assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(path));
        Map<String, String> context = new LinkedHashMap<>(base);
        context.put("context", "\"injected\"");
        assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(context));
        Map<String, String> missing = new LinkedHashMap<>(base);
        missing.remove("ciphertext");
        assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(missing));
    }

    @Test
    void itsDescriptionNamesThePathNotTheCiphertext() throws Exception {
        try (FakeVaultServer vault = new FakeVaultServer(context, new FakeVaultServer.Script());
             SecretProvider provider = SecretProviders.of(settings(vault))) {
            assertTrue(provider.toString().contains("/v1/transit/decrypt/field-data"));
            assertFalse(provider.toString().contains("vault:v1"));
        }
    }
}
