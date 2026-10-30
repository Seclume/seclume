package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import java.util.Random;

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
 * {@code provider=kms-decrypt} against a stand-in for each service: what is
 * asked of AWS KMS, Cloud KMS and Key Vault, the plaintext decoded from each
 * answer's Base64 (Key Vault's Base64url), and every answer that is not one.
 * The request shapes and the answers are those of the services' API
 * references; AWS's signature is {@code AwsJsonCall}'s, tested elsewhere.
 */
@Timeout(120)
class KmsDecryptSecretProviderTest {

    private static final Random RANDOM = new Random(20261030L);
    private static final String GCP_KEY =
            "projects/p/locations/europe-west3/keyRings/r/cryptoKeys/field-data";
    private static final String CIPHERTEXT = "AQICAHh+0wW/5vNyF3k7n0fEW3Oe4Vqk/AA==";

    private static TestCertificates certificates;
    private static SSLContext context;

    @TempDir
    static Path directory;
    private static Path token;
    private static Path awsSecret;

    @BeforeAll
    static void anAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        context = FakeVaultServer.context(certificates);
        token = Files.writeString(directory.resolve("token"), "ya29.a-bearer-token\n");
        awsSecret = Files.writeString(directory.resolve("aws"),
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    }

    @AfterAll
    static void removeIt() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    private static byte[] key() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return key;
    }

    private static byte[] read(SecretProvider provider) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            int length = provider.writeSecret(target);
            return target.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
        }
    }

    // ------------------------------------------------------------------- AWS

    private static Map<String, String> aws(FakeVaultServer kms) {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "kms-decrypt");
        settings.put("kms", "aws-kms");
        settings.put("key", "arn:aws:kms:eu-central-1:111122223333:alias/field-data");
        settings.put("region", "eu-central-1");
        settings.put("endpoint", kms.address());
        settings.put("verify", "false");
        settings.put("ciphertext", CIPHERTEXT);
        settings.put("access-key-id", "AKIDEXAMPLE");
        settings.put("key-provider", "file");
        settings.put("key-path", awsSecret.toString());
        return settings;
    }

    @Test
    void awsKmsDecryptsWithTheKeyNamedAndSigned() throws Exception {
        byte[] plain = key();
        try (FakeVaultServer kms = new FakeVaultServer(context, request -> new FakeVaultServer
                .Answer(200, "{\"KeyId\":\"arn:aws:kms:eu-central-1:111122223333:key/1\","
                        + "\"Plaintext\":\"" + Base64.getEncoder().encodeToString(plain)
                        + "\",\"EncryptionAlgorithm\":\"SYMMETRIC_DEFAULT\"}"));
             SecretProvider provider = SecretProviders.of(aws(kms))) {
            assertArrayEquals(plain, read(provider));
            FakeVaultServer.Request request = kms.requests().get(0);
            assertEquals("POST", request.method());
            assertEquals("TrentService.Decrypt", request.header("X-Amz-Target"));
            assertTrue(request.header("Authorization").startsWith(
                    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"), request.header("Authorization"));
            assertTrue(request.header("Authorization").contains("/eu-central-1/kms/aws4_request"));
            assertEquals("{\"CiphertextBlob\":\"" + CIPHERTEXT + "\",\"KeyId\":\"arn:aws:kms:"
                    + "eu-central-1:111122223333:alias/field-data\",\"EncryptionAlgorithm\":"
                    + "\"SYMMETRIC_DEFAULT\"}", request.body());
            assertFalse(request.toString().contains("wJalrXUtnFEMI"),
                    "the secret access key went out");
        }
    }

    @Test
    void awsKmsRefusalsSayWhatIsNeeded() throws Exception {
        try (FakeVaultServer kms = new FakeVaultServer(context, request -> new FakeVaultServer
                .Answer(400, "{\"__type\":\"IncorrectKeyException\",\"message\":\"The key ID "
                        + "in the request does not identify a CMK that can perform this "
                        + "operation.\"}"));
             SecretProvider provider = SecretProviders.of(aws(kms))) {
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                    () -> read(provider));
            assertTrue(e.getMessage().contains("IncorrectKeyException"), e.getMessage());
            assertTrue(e.getMessage().contains("kms:Decrypt"), e.getMessage());
        }
    }

    // ------------------------------------------------------------------- GCP

    private static Map<String, String> gcp(FakeVaultServer kms) {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "kms-decrypt");
        settings.put("kms", "gcp-kms");
        settings.put("key", GCP_KEY);
        settings.put("endpoint", kms.address());
        settings.put("verify", "false");
        settings.put("ciphertext", CIPHERTEXT);
        settings.put("token-provider", "file");
        settings.put("token-path", token.toString());
        return settings;
    }

    @Test
    void cloudKmsDecryptsAtTheCryptoKey() throws Exception {
        byte[] plain = key();
        FakeVaultServer.Script script = new FakeVaultServer.Script().on("POST",
                "/v1/" + GCP_KEY + ":decrypt", 200, "{\"plaintext\":\""
                        + Base64.getEncoder().encodeToString(plain)
                        + "\",\"plaintextCrc32c\":\"123\",\"usedPrimary\":true}");
        try (FakeVaultServer kms = new FakeVaultServer(context, script);
             SecretProvider provider = SecretProviders.of(gcp(kms))) {
            assertArrayEquals(plain, read(provider));
            FakeVaultServer.Request request = kms.requests().get(0);
            assertEquals("Bearer ya29.a-bearer-token", request.header("Authorization"));
            assertEquals("{\"ciphertext\":\"" + CIPHERTEXT + "\"}", request.body());
        }
    }

    @Test
    void cloudKmsRefusalsSayWhatIsNeeded() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script().on("POST",
                "/v1/" + GCP_KEY + ":decrypt", 403, "{\"error\":{\"code\":403,\"message\":"
                        + "\"Permission 'cloudkms.cryptoKeyVersions.useToDecrypt' denied\","
                        + "\"status\":\"PERMISSION_DENIED\"}}");
        try (FakeVaultServer kms = new FakeVaultServer(context, script);
             SecretProvider provider = SecretProviders.of(gcp(kms))) {
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                    () -> read(provider));
            assertTrue(e.getMessage().contains("403"), e.getMessage());
            assertTrue(e.getMessage().contains("Permission 'cloudkms"), e.getMessage());
            assertTrue(e.getMessage().contains("useToDecrypt on " + GCP_KEY), e.getMessage());
        }
    }

    @Test
    void aKeyVersionIsNotACryptoKey() {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "kms-decrypt");
        settings.put("kms", "gcp-kms");
        settings.put("key", GCP_KEY + "/cryptoKeyVersions/1");
        settings.put("ciphertext", CIPHERTEXT);
        settings.put("token-provider", "file");
        settings.put("token-path", token.toString());
        assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(settings));
    }

    // ----------------------------------------------------------------- Azure

    private static Map<String, String> azure(FakeVaultServer vault) {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "kms-decrypt");
        settings.put("kms", "azure-key-vault");
        settings.put("vault-uri", vault.address());
        settings.put("verify", "false");
        settings.put("key-name", "field-kek");
        settings.put("key-version", "0123456789abcdef0123456789abcdef");
        settings.put("ciphertext", "q-_8w-_x");
        settings.put("token-provider", "file");
        settings.put("token-path", token.toString());
        return settings;
    }

    /** Key Vault answers Base64url, whose '-' and '_' have to become the right bytes. */
    @Test
    void keyVaultUnwrapsAndItsBase64UrlIsDecoded() throws Exception {
        byte[] plain = new byte[32];
        for (int i = 0; i < plain.length; i++) {
            plain[i] = (byte) (0xf8 + (i & 7));          // 0xfb.. 0xff: '-' and '_' guaranteed
        }
        String url = Base64.getUrlEncoder().withoutPadding().encodeToString(plain);
        assertTrue(url.contains("-") || url.contains("_"), url);
        FakeVaultServer.Script script = new FakeVaultServer.Script().on("POST",
                "/keys/field-kek/0123456789abcdef0123456789abcdef/unwrapkey?api-version=7.4", 200,
                "{\"kid\":\"https://v.vault.azure.net/keys/field-kek/0123\",\"value\":\""
                        + url + "\"}");
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             SecretProvider provider = SecretProviders.of(azure(vault))) {
            assertArrayEquals(plain, read(provider));
            FakeVaultServer.Request request = vault.requests().get(0);
            assertEquals("{\"alg\":\"RSA-OAEP-256\",\"value\":\"q-_8w-_x\"}", request.body());
            assertEquals("Bearer ya29.a-bearer-token", request.header("Authorization"));
        }
    }

    @Test
    void keyVaultNeedsTheVersionAndAKnownAlgorithm() {
        try (FakeVaultServer vault = new FakeVaultServer(context, new FakeVaultServer.Script())) {
            Map<String, String> noVersion = azure(vault);
            noVersion.remove("key-version");
            assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(noVersion));
            Map<String, String> algorithm = azure(vault);
            algorithm.put("algorithm", "RSA1_5");
            assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(algorithm));
            Map<String, String> http = azure(vault);
            http.put("vault-uri", "http://127.0.0.1:1");
            assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(http));
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    // ---------------------------------------------------------------- shared

    @Test
    void answersThatAreNotAPlaintextAreRefused() throws Exception {
        for (String body : new String[] {"{}", "{\"plaintext\":17}", "{\"plaintext\":\"*\"}",
                "not json", "{\"plaintext\":", "{\"error\":{\"message\":\"x\"}}"}) {
            FakeVaultServer.Script script = new FakeVaultServer.Script().on("POST",
                    "/v1/" + GCP_KEY + ":decrypt", 200, body);
            try (FakeVaultServer kms = new FakeVaultServer(context, script);
                 SecretProvider provider = SecretProviders.of(gcp(kms))) {
                assertThrows(SecretUnavailableException.class, () -> read(provider), body);
            }
        }
    }

    @Test
    void aPlaintextLargerThanAllowedIsRefused() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script().on("POST",
                "/v1/" + GCP_KEY + ":decrypt", 200, "{\"plaintext\":\""
                        + Base64.getEncoder().encodeToString(new byte[500]) + "\"}");
        try (FakeVaultServer kms = new FakeVaultServer(context, script)) {
            Map<String, String> settings = gcp(kms);
            settings.put("max-length", "64");
            try (SecretProvider provider = SecretProviders.of(settings)) {
                SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                        () -> read(provider));
                assertTrue(e.getMessage().contains("max-length"), e.getMessage());
            }
        }
    }

    @Test
    void theSettingsAreCheckedBeforeAnythingIsAsked() throws Exception {
        try (FakeVaultServer kms = new FakeVaultServer(context, new FakeVaultServer.Script())) {
            Map<String, String> none = gcp(kms);
            none.remove("kms");
            assertTrue(assertThrows(IllegalArgumentException.class,
                    () -> SecretProviders.of(none)).getMessage().contains("kms="));
            Map<String, String> unknown = gcp(kms);
            unknown.put("kms", "oracle-vault");
            assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(unknown));
            for (String bad : new String[] {"", "not base64!", "AA\"}AA", "vault:v1:AA"}) {
                Map<String, String> settings = gcp(kms);
                settings.put("ciphertext", bad);
                assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(settings),
                        bad);
            }
            Map<String, String> region = aws(kms);
            region.put("region", "EU Central");
            assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(region));
            Map<String, String> noCredentials = aws(kms);
            noCredentials.remove("key-provider");
            noCredentials.remove("key-path");
            assertThrows(IllegalArgumentException.class,
                    () -> SecretProviders.of(noCredentials));
            Map<String, String> plainHttp = gcp(kms);
            plainHttp.put("endpoint", "http://127.0.0.1:1");
            assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(plainHttp));
        }
    }

    @Test
    void vaultTransitIsTheSameAsItsOwnProvider() throws Exception {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "kms-decrypt");
        settings.put("kms", "vault-transit");
        settings.put("address", "https://127.0.0.1:1");
        settings.put("key-name", "field-data");
        settings.put("ciphertext", "vault:v1:AAAA");
        settings.put("token-provider", "file");
        settings.put("token-path", token.toString());
        try (SecretProvider provider = SecretProviders.of(settings)) {
            assertInstanceOf(VaultTransitSecretProvider.class, provider);
        }
    }

    @Test
    void aDataKeyFromEachCloudKeysAFieldRing() throws Exception {
        byte[] plain = key();
        String b64 = Base64.getEncoder().encodeToString(plain);
        try (FakeVaultServer kms = new FakeVaultServer(context, request -> new FakeVaultServer
                .Answer(200, "{\"Plaintext\":\"" + b64 + "\",\"plaintext\":\"" + b64
                        + "\",\"value\":\"" + Base64.getUrlEncoder().encodeToString(plain)
                        + "\"}"))) {
            Map<String, String> azure = azure(kms);
            byte[] reference = null;
            for (Map<String, String> settings : java.util.List.of(aws(kms), gcp(kms), azure)) {
                try (FieldKeys keys = FieldKeys.builder().key(1, SecretProviders.of(settings))
                        .build()) {
                    byte[] value = keys.column("t.c", EncryptedColumn.Mode.DETERMINISTIC)
                            .encrypt(MemorySegment.ofArray("x".getBytes(StandardCharsets.UTF_8)));
                    if (reference == null) {
                        reference = value;
                    }
                    assertArrayEquals(reference, value, settings.get("kms")
                            + " opened another key than the other services");
                }
            }
            assertNotNull(reference);
            assertEquals(3, kms.requests().size());
        }
    }

    /** The '-' and '_' mapping, over every byte value: nothing else changes. */
    @Test
    void theUrlAlphabetMapsTwoCharactersAndNothingElse() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = arena.allocate(256);
            for (int i = 0; i < 256; i++) {
                text.set(ValueLayout.JAVA_BYTE, i, (byte) i);
            }
            KmsDecryptSecretProvider.fromUrlAlphabet(text, 256);
            for (int i = 0; i < 256; i++) {
                int expected = i == '-' ? '+' : i == '_' ? '/' : i;
                assertEquals(expected, text.get(ValueLayout.JAVA_BYTE, i) & 0xff, "byte " + i);
            }
        }
    }
}
