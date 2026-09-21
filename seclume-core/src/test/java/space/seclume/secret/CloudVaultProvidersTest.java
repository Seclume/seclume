package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.AwsSigV4;
import space.seclume.tls.TestCertificates;

/**
 * The three cloud vaults, against HTTPS servers that answer the way they do.
 *
 * <p>Each of the three has a different shape and each shape is where the
 * mistake would be: AWS puts a JSON document inside a JSON string, Azure puts
 * the expiry in a sibling object, Google Base64-encodes the payload. All three
 * are read here without the secret becoming a {@code String} at any point, and
 * the assertions are on what came out the far end.
 *
 * <p>What these tests cannot do is prove the providers agree with the real
 * services - the answers are recorded shapes, and a provider changing its API
 * would leave this green. What they do prove is everything on this side: the
 * signing, the request, the parsing, the decoding, and the error messages.
 */
@Timeout(120)
class CloudVaultProvidersTest {

    private static TestCertificates certificates;
    private static SSLContext serverContext;

    @BeforeAll
    static void anAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued endpoint = certificates.issue("cloud",
                "san=ip:127.0.0.1", "eku=serverAuth");

        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(endpoint.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        serverContext = SSLContext.getInstance("TLSv1.3");
        serverContext.init(keys.getKeyManagers(), null, null);
    }

    @AfterAll
    static void removeIt() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    /** One HTTPS endpoint with a canned answer, recording what it was asked. */
    private static final class Endpoint implements AutoCloseable {

        private final SSLServerSocket socket;
        private final List<String> requests = new CopyOnWriteArrayList<>();
        private final String body;
        private final int status;
        private volatile boolean stopped;

        Endpoint(int status, String body) throws IOException {
            this.status = status;
            this.body = body;
            this.socket = (SSLServerSocket) serverContext.getServerSocketFactory()
                    .createServerSocket(0, 4, InetAddress.getLoopbackAddress());
            this.socket.setSoTimeout(30_000);
            Thread thread = new Thread(this::serve, "fake-cloud-vault");
            thread.setDaemon(true);
            thread.start();
        }

        private void serve() {
            while (!stopped) {
                try (SSLSocket accepted = (SSLSocket) socket.accept()) {
                    accepted.setSoTimeout(30_000);
                    requests.add(readRequest(accepted.getInputStream()));
                    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                    OutputStream out = accepted.getOutputStream();
                    out.write(("HTTP/1.1 " + status + " \r\n"
                            + "Content-Type: application/json\r\n"
                            + "Content-Length: " + bytes.length + "\r\n"
                            + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    out.write(bytes);
                    out.flush();
                } catch (Exception e) {
                    if (stopped) {
                        return;
                    }
                }
            }
        }

        /** Headers and, for a POST, the body that follows them. */
        private static String readRequest(InputStream in) throws IOException {
            StringBuilder text = new StringBuilder();
            int b;
            while ((b = in.read()) >= 0) {
                text.append((char) b);
                if (text.length() >= 4 && text.indexOf("\r\n\r\n", text.length() - 4) >= 0) {
                    break;
                }
            }
            int length = contentLength(text.toString());
            for (int i = 0; i < length && (b = in.read()) >= 0; i++) {
                text.append((char) b);
            }
            return text.toString();
        }

        private static int contentLength(String headers) {
            for (String line : headers.split("\r\n")) {
                if (line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:")) {
                    return Integer.parseInt(line.substring(line.indexOf(':') + 1).trim());
                }
            }
            return 0;
        }

        int port() {
            return socket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            stopped = true;
            socket.close();
        }
    }

    private static SecretProvider literal(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
        return new CallbackSecretProvider(bytes.length, target -> {
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
    }

    private static String read(SecretProvider provider) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            int length = provider.writeSecret(target);
            byte[] bytes = new byte[length];
            MemorySegment.copy(target, ValueLayout.JAVA_BYTE, 0, bytes, 0, length);
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    // --------------------------------------------- AWS Secrets Manager ----

    private static AwsSecretsManagerSecretProvider aws(Endpoint endpoint, String field) {
        return new AwsSecretsManagerSecretProvider(literal("wJalrXUtnFEMI/K7MDENG"),
                "AKIAIOSFODNN7EXAMPLE", "eu-central-1", "prod/db", field,
                "127.0.0.1", endpoint.port(), false, 10_000, 512,
                Clock.fixed(Instant.parse("2026-09-20T12:00:00Z"), ZoneOffset.UTC));
    }

    /** The common case AWS itself pushes: a JSON document inside SecretString. */
    @Test
    void awsReadsAFieldOutOfTheSecretJson() throws Exception {
        String answer = "{\"ARN\":\"arn:aws:secretsmanager:eu-central-1:1:secret:prod/db\","
                + "\"Name\":\"prod/db\","
                + "\"SecretString\":\"{\\\"username\\\":\\\"app\\\",\\\"password\\\":\\\"s3cr3t\\\"}\","
                + "\"VersionId\":\"v1\"}";

        try (Endpoint endpoint = new Endpoint(200, answer);
             AwsSecretsManagerSecretProvider provider = aws(endpoint, "password")) {

            assertEquals("s3cr3t", read(provider));

            String request = endpoint.requests.get(0);
            assertTrue(request.startsWith("POST / HTTP/1.1"), request);
            assertTrue(request.contains("X-Amz-Target: secretsmanager.GetSecretValue"), request);
            assertTrue(request.contains("{\"SecretId\":\"prod/db\"}"), request);
        }
    }

    /** Without a field the whole SecretString is the secret. */
    @Test
    void awsTakesTheWholeSecretStringWhenNoFieldIsNamed() throws Exception {
        try (Endpoint endpoint = new Endpoint(200, "{\"SecretString\":\"just-a-password\"}");
             AwsSecretsManagerSecretProvider provider = aws(endpoint, null)) {

            assertEquals("just-a-password", read(provider));
        }
    }

    /**
     * The Authorization header is a full SigV4 header, not a stub.
     *
     * <p>Checked in shape rather than against a known-answer vector: the
     * signing chain itself has one of those in {@code RdsIamSecretProviderTest},
     * and what is new here is the header-signed variant - the credential
     * scope, the signed header list, and a signature of the right length.
     */
    @Test
    void awsSignsWithTheHeaderVariant() throws Exception {
        try (Endpoint endpoint = new Endpoint(200, "{\"SecretString\":\"x\"}");
             AwsSecretsManagerSecretProvider provider = aws(endpoint, null)) {

            read(provider);
            String request = endpoint.requests.get(0);
            assertTrue(request.contains(
                    "Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE"
                    + "/20260920/eu-central-1/secretsmanager/aws4_request"), request);
            assertTrue(request.contains(
                    "SignedHeaders=content-type;host;x-amz-date;x-amz-target"), request);
            assertTrue(request.contains("X-Amz-Date: 20260920T120000Z"), request);

            String signature = request.substring(request.indexOf("Signature=") + 10);
            signature = signature.substring(0, signature.indexOf('\r'));
            assertEquals(64, signature.length(), "a SHA-256 signature is 64 hex characters");
            assertTrue(signature.matches("[0-9a-f]{64}"), signature);
        }
    }

    /**
     * Temporary credentials: the session token is sent <b>and signed</b>.
     *
     * <p>Sending it is the easy half, and a test that only looked for the
     * header would pass while the signature ignored it - which AWS rejects
     * with a message that says nothing useful. So the expected
     * {@code Authorization} is recomputed here from a canonical request
     * built as an ordinary string, token and all, and compared with what the
     * provider produced. The test may hold the token as a {@code String};
     * the provider may not, and that difference is the whole feature.
     */
    @Test
    void awsSignsTheSessionTokenAndNotOnlySendsIt() throws Exception {
        String token = "FwoGZXIvYXdzEExampleSessionToken";
        try (Endpoint endpoint = new Endpoint(200, "{\"SecretString\":\"x\"}");
             AwsSecretsManagerSecretProvider provider = new AwsSecretsManagerSecretProvider(
                     literal("wJalrXUtnFEMI/K7MDENG"), literal(token),
                     "AKIAIOSFODNN7EXAMPLE", "eu-central-1", "prod/db", null,
                     "127.0.0.1", endpoint.port(), false, 10_000, 512,
                     Clock.fixed(Instant.parse("2026-09-20T12:00:00Z"), ZoneOffset.UTC))) {

            read(provider);
            String request = endpoint.requests.get(0);

            assertTrue(request.contains("X-Amz-Security-Token: " + token),
                    "the token was not sent: " + request);
            assertTrue(request.contains("SignedHeaders=content-type;host;x-amz-date;"
                    + "x-amz-security-token;x-amz-target"),
                    "the token was not named in the signed headers: " + request);
            assertEquals(expectedAuthorization(token), authorizationOf(request),
                    "the signature does not cover the session token");
        }
    }

    /** Without a token nothing changes - the regression guard for the above. */
    @Test
    void awsWithoutATokenSignsExactlyAsBefore() throws Exception {
        try (Endpoint endpoint = new Endpoint(200, "{\"SecretString\":\"x\"}");
             AwsSecretsManagerSecretProvider provider = aws(endpoint, null)) {

            read(provider);
            String request = endpoint.requests.get(0);
            assertTrue(!request.contains("X-Amz-Security-Token"), request);
            assertEquals(expectedAuthorization(null), authorizationOf(request));
        }
    }

    /**
     * What this request should carry, worked out independently.
     *
     * <p>Built the old way, by concatenation - which is exactly what the
     * provider is no longer allowed to do. The two agreeing means the
     * segment-assembled canonical request is byte for byte the one AWS
     * expects, which is the only thing that can be checked from outside: a
     * signature over a canonical request that is one character different is
     * a perfectly well-formed signature.
     */
    private static String expectedAuthorization(String token) {
        String stamp = "20260920T120000Z";
        String day = "20260920";
        String region = "eu-central-1";
        String service = "secretsmanager";
        // Without the port, because that is what goes on the wire: the Host
        // header and the canonical request have to be the same string, and
        // SecretFetch sends the bare name. Getting this wrong here was the
        // first thing the no-token control caught, which is what it is for.
        String host = "127.0.0.1";
        String signedHeaders = token == null
                ? "content-type;host;x-amz-date;x-amz-target"
                : "content-type;host;x-amz-date;x-amz-security-token;x-amz-target";
        String canonical = "POST\n/\n\n"
                + "content-type:application/x-amz-json-1.1\n"
                + "host:" + host + "\n"
                + "x-amz-date:" + stamp + "\n"
                + (token == null ? "" : "x-amz-security-token:" + token + "\n")
                + "x-amz-target:secretsmanager.GetSecretValue\n\n"
                + signedHeaders + "\n"
                + AwsSigV4.sha256Hex("{\"SecretId\":\"prod/db\"}");
        String scope = AwsSigV4.scope(day, region, service);
        String toSign = AwsSigV4.ALGORITHM + "\n" + stamp + "\n" + scope + "\n"
                + AwsSigV4.sha256Hex(canonical);
        try (Arena arena = Arena.ofConfined()) {
            byte[] key = "wJalrXUtnFEMI/K7MDENG".getBytes(StandardCharsets.US_ASCII);
            MemorySegment signature = AwsSigV4.sign(arena, target -> {
                MemorySegment.copy(key, 0, target, ValueLayout.JAVA_BYTE, 0, key.length);
                return key.length;
            }, toSign, day, region, service);
            return AwsSigV4.ALGORITHM + " Credential=AKIAIOSFODNN7EXAMPLE/" + scope
                    + ", SignedHeaders=" + signedHeaders
                    + ", Signature=" + AwsSigV4.hex(signature);
        }
    }

    private static String authorizationOf(String request) {
        int at = request.indexOf("Authorization: ");
        assertTrue(at >= 0, request);
        return request.substring(at + "Authorization: ".length(), request.indexOf("\r\n", at));
    }

    @Test
    void awsSaysWhatA403Means() throws Exception {
        try (Endpoint endpoint = new Endpoint(403, "{\"__type\":\"AccessDeniedException\"}");
             AwsSecretsManagerSecretProvider provider = aws(endpoint, null)) {

            SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                    () -> read(provider));
            assertTrue(refused.getMessage().contains("403"), refused.getMessage());
        }
    }

    // ---------------------------------------------- Azure Key Vault ------

    @Test
    void azureReadsTheValueAndSendsTheBearerToken() throws Exception {
        String answer = "{\"value\":\"azure-password\","
                + "\"id\":\"https://v.vault.azure.net/secrets/db/1\","
                + "\"attributes\":{\"enabled\":true,\"created\":1758000000}}";

        try (Endpoint endpoint = new Endpoint(200, answer);
             AzureKeyVaultSecretProvider provider = new AzureKeyVaultSecretProvider(
                     "https://127.0.0.1:" + endpoint.port(), "db", null,
                     literal("eyJhbGciOiJSUzI1NiJ9.token"), false, 10_000, 256)) {

            assertEquals("azure-password", read(provider));
            assertNull(provider.credentialsValidUntil(), "this secret has no expiry set");

            String request = endpoint.requests.get(0);
            assertTrue(request.startsWith("GET /secrets/db?api-version=7.4 HTTP/1.1"), request);
            assertTrue(request.contains("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.token"),
                    request);
        }
    }

    /** A secret with an expiry reports it, and the pool can act on it. */
    @Test
    void azureReportsAnExpiryWhenTheSecretHasOne() throws Exception {
        long exp = Instant.parse("2026-09-21T00:00:00Z").getEpochSecond();
        String answer = "{\"value\":\"rotating\",\"attributes\":{\"enabled\":true,"
                + "\"exp\":" + exp + "}}";

        try (Endpoint endpoint = new Endpoint(200, answer);
             AzureKeyVaultSecretProvider provider = new AzureKeyVaultSecretProvider(
                     "https://127.0.0.1:" + endpoint.port(), "db", null,
                     literal("token"), false, 10_000, 256)) {

            assertEquals("rotating", read(provider));
            assertEquals(Instant.ofEpochSecond(exp), provider.credentialsValidUntil());
        }
    }

    @Test
    void azureAsksForANamedVersionWhenGivenOne() throws Exception {
        try (Endpoint endpoint = new Endpoint(200, "{\"value\":\"v2\"}");
             AzureKeyVaultSecretProvider provider = new AzureKeyVaultSecretProvider(
                     "https://127.0.0.1:" + endpoint.port(), "db", "abc123",
                     literal("token"), false, 10_000, 256)) {

            assertEquals("v2", read(provider));
            assertTrue(endpoint.requests.get(0).startsWith(
                    "GET /secrets/db/abc123?api-version=7.4"), endpoint.requests.get(0));
        }
    }

    @Test
    void azureRefusesPlainHttpAtConstruction() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> new AzureKeyVaultSecretProvider("http://v.vault.azure.net", "db", null,
                        literal("token"), 256));
        assertTrue(refused.getMessage().contains("token given away"), refused.getMessage());
    }

    // --------------------------------------------- GCP Secret Manager ----

    @Test
    void googleDecodesTheBase64Payload() throws Exception {
        String password = "google-paßwort";
        String encoded = Base64.getEncoder().encodeToString(
                password.getBytes(StandardCharsets.UTF_8));
        String answer = "{\"name\":\"projects/p/secrets/db/versions/3\","
                + "\"payload\":{\"data\":\"" + encoded + "\",\"dataCrc32c\":\"123\"}}";

        try (Endpoint endpoint = new Endpoint(200, answer);
             GcpSecretManagerSecretProvider provider = new GcpSecretManagerSecretProvider(
                     "my-project", "db", null, literal("ya29.token"),
                     "127.0.0.1", endpoint.port(), false, 10_000, 256)) {

            assertEquals(password, read(provider));

            String request = endpoint.requests.get(0);
            assertTrue(request.startsWith(
                    "GET /v1/projects/my-project/secrets/db/versions/latest:access HTTP/1.1"),
                    request);
            assertTrue(request.contains("Authorization: Bearer ya29.token"), request);
        }
    }

    @Test
    void googleAsksForANamedVersion() throws Exception {
        String answer = "{\"payload\":{\"data\":\""
                + Base64.getEncoder().encodeToString("v7".getBytes(StandardCharsets.UTF_8))
                + "\"}}";

        try (Endpoint endpoint = new Endpoint(200, answer);
             GcpSecretManagerSecretProvider provider = new GcpSecretManagerSecretProvider(
                     "my-project", "db", "7", literal("token"),
                     "127.0.0.1", endpoint.port(), false, 10_000, 256)) {

            assertEquals("v7", read(provider));
            assertTrue(endpoint.requests.get(0).contains("/versions/7:access"),
                    endpoint.requests.get(0));
        }
    }

    @Test
    void googleSaysWhenThePayloadIsNotBase64() throws Exception {
        try (Endpoint endpoint = new Endpoint(200,
                "{\"payload\":{\"data\":\"not base64 !!\"}}");
             GcpSecretManagerSecretProvider provider = new GcpSecretManagerSecretProvider(
                     "p", "db", null, literal("token"),
                     "127.0.0.1", endpoint.port(), false, 10_000, 256)) {

            SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                    () -> read(provider));
            assertTrue(refused.getMessage().contains("Base64"), refused.getMessage());
        }
    }

    // ------------------------------------------------------- the registry --

    @Test
    void allThreeAreReachableByConfiguration(@org.junit.jupiter.api.io.TempDir Path dir)
            throws Exception {
        Path token = dir.resolve("token");
        Files.writeString(token, "bearer-from-file");

        try (Endpoint endpoint = new Endpoint(200, "{\"value\":\"configured\"}")) {
            Map<String, String> settings = new LinkedHashMap<>();
            settings.put("provider", "azure-key-vault");
            settings.put("vault-uri", "https://127.0.0.1:" + endpoint.port());
            settings.put("name", "db");
            settings.put("token-provider", "file");
            settings.put("token-path", token.toString());

            // The registry builds the verifying variant, which cannot reach a
            // certificate nobody trusts - so this proves the wiring up to the
            // point where the transport takes over.
            try (SecretProvider provider = SecretProviders.of(settings)) {
                assertThrows(SecretUnavailableException.class, () -> read(provider));
            }
        }

        for (String kind : List.of("aws-secrets-manager", "gcp-secret-manager")) {
            Map<String, String> settings = new LinkedHashMap<>();
            settings.put("provider", kind);
            IllegalArgumentException incomplete = assertThrows(IllegalArgumentException.class,
                    () -> SecretProviders.of(settings));
            assertTrue(incomplete.getMessage().contains(kind), incomplete.getMessage());
        }
    }

    /** An unknown provider names all of them, so the list stays honest. */
    @Test
    void theErrorMessageListsTheNewProviders() {
        IllegalArgumentException unknown = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(Map.of("provider", "nonesuch")));
        assertTrue(unknown.getMessage().contains("aws-secrets-manager"), unknown.getMessage());
        assertTrue(unknown.getMessage().contains("azure-key-vault"), unknown.getMessage());
        assertTrue(unknown.getMessage().contains("gcp-secret-manager"), unknown.getMessage());
        assertTrue(unknown.getMessage().contains("vault"), unknown.getMessage());
    }

    /** Nothing is left open, whichever way a cloud fetch ends. */
    @Test
    void nothingIsLeftOpenOnFailure() throws Exception {
        long open = SecretScope.open();
        try (Endpoint endpoint = new Endpoint(500, "{\"error\":\"boom\"}");
             AzureKeyVaultSecretProvider provider = new AzureKeyVaultSecretProvider(
                     "https://127.0.0.1:" + endpoint.port(), "db", null,
                     literal("token"), false, 10_000, 256)) {

            assertThrows(SecretUnavailableException.class, () -> read(provider));
        }
        assertEquals(open, SecretScope.open());
    }
}
