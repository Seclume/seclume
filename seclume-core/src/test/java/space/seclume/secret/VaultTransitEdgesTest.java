package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
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

import space.seclume.tls.TestCertificates;

/**
 * {@code provider=vault-transit} at its edges: a plaintext of exactly
 * max-length and one or three bytes more, a ciphertext abbreviated at 24
 * characters in its refusal, the port an address names or the default, and
 * the namespace header sent only when there is a namespace. Written against
 * the mutants PIT left alive in this package.
 */
@Timeout(120)
class VaultTransitEdgesTest {

    private static final String CIPHERTEXT = "vault:v2:QUJDREVGR0hJSktMTU5PUFFSU1RVVldY";

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
        token = Files.writeString(directory.resolve("token"), "hvs.transit-edges\n");
    }

    @AfterAll
    static void removeIt() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    private static Map<String, String> settings(String address) {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "vault-transit");
        settings.put("address", address);
        settings.put("verify", "false");
        settings.put("key-name", "edges");
        settings.put("ciphertext", CIPHERTEXT);
        settings.put("token-provider", "file");
        settings.put("token-path", token.toString());
        settings.put("max-length", "32");
        return settings;
    }

    private static String answer(int length) {
        byte[] plaintext = new byte[length];
        Arrays.fill(plaintext, (byte) 0x3c);
        return "{\"data\":{\"plaintext\":\"" + Base64.getEncoder().encodeToString(plaintext) + "\"}}";
    }

    private static byte[] read(SecretProvider provider) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            int length = provider.writeSecret(target);
            return target.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
        }
    }

    private static String refusalFor(int length) throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/transit/decrypt/edges", 200, answer(length));
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             SecretProvider provider = SecretProviders.of(settings(vault.address()))) {
            return assertThrows(SecretUnavailableException.class, () -> read(provider)).getMessage();
        }
    }

    @Test
    void aPlaintextOfExactlyMaxLengthFitsAndOneByteMoreDoesNot() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/transit/decrypt/edges", 200, answer(32), answer(1));
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             SecretProvider provider = SecretProviders.of(settings(vault.address()))) {
            assertEquals(32, provider.maxSecretLength());
            byte[] expected = new byte[32];
            Arrays.fill(expected, (byte) 0x3c);
            assertArrayEquals(expected, read(provider));
            assertArrayEquals(new byte[] {0x3c}, read(provider));
        }
        assertEquals("the decrypted secret is 33 bytes and does not fit into the 32 bytes provided - raise max-length",
                refusalFor(33));
        assertEquals("the decrypted secret does not fit into the 32 bytes provided - raise max-length",
                refusalFor(35), "four Base64 characters more than the target can take, refused before decoding");
    }

    @Test
    void aWrongCiphertextIsAbbreviatedAfter24Characters() {
        Map<String, String> settings = settings("https://127.0.0.1:8200");
        settings.put("ciphertext", "x".repeat(24));
        IllegalArgumentException exact = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(settings));
        assertTrue(exact.getMessage().endsWith(" - not " + "x".repeat(24)), exact.getMessage());
        settings.put("ciphertext", "y".repeat(25));
        IllegalArgumentException longer = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(settings));
        assertTrue(longer.getMessage().endsWith(" - not " + "y".repeat(24) + "..."), longer.getMessage());
    }

    @Test
    void thePortIsTheAddresssOrHttpsDefault() {
        try (SecretProvider named = SecretProviders.of(settings("https://vault.example:8201"));
             SecretProvider plain = SecretProviders.of(settings("https://vault.example"))) {
            assertEquals("VaultTransitSecretProvider[vault.example:8201/v1/transit/decrypt/edges]", named.toString());
            assertEquals("VaultTransitSecretProvider[vault.example:443/v1/transit/decrypt/edges]", plain.toString());
        }
    }

    @Test
    void theNamespaceHeaderIsSentOnlyWithANamespace() throws Exception {
        for (String namespace : new String[] {null, "", "  ", "team-b"}) {
            FakeVaultServer.Script script = new FakeVaultServer.Script()
                    .on("POST", "/v1/transit/decrypt/edges", 200, answer(4));
            try (FakeVaultServer vault = new FakeVaultServer(context, script)) {
                Map<String, String> settings = settings(vault.address());
                if (namespace != null) {
                    settings.put("namespace", namespace);
                }
                try (SecretProvider provider = SecretProviders.of(settings)) {
                    read(provider);
                }
                String sent = vault.requests().get(0).header("X-Vault-Namespace");
                if ("team-b".equals(namespace)) {
                    assertEquals("team-b", sent);
                } else {
                    assertNull(sent, "'" + namespace + "'");
                }
            }
        }
    }
}
