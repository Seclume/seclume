package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.tls.TestCertificates;

/**
 * Logging in to Vault with a cloud identity - AWS IAM, GCP, Azure - against
 * {@link FakeVaultServer} and stand-ins for the metadata services.
 *
 * <p>The AWS request is the one that has to be exactly right: Vault does not
 * check it, it replays it to AWS, and AWS recomputes the signature. So the
 * test takes the request apart and recomputes the SigV4 signature itself,
 * with the JDK's HMAC and the published algorithm - an implementation that
 * shares no code with the one under test.
 */
@Timeout(120)
@org.junit.jupiter.api.parallel.Isolated
class VaultCloudLoginTest {

    private static final Instant NOW = Instant.parse("2026-10-29T08:15:30Z");
    private static final String KEY_ID = "AKIAIOSFODNN7EXAMPLE";
    /** AWS's own documentation example key - nothing real. */
    private static final String SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    private static TestCertificates certificates;
    private static SSLContext context;

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

    private static String login(String token) {
        return "{\"auth\":{\"client_token\":\"" + token + "\",\"lease_duration\":3600,"
                + "\"renewable\":true}}";
    }

    private static SecretProvider fixed(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return new CallbackSecretProvider(16_384, target -> {
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

    /** The string fields of a flat JSON object - enough for the bodies these logins send. */
    private static Map<String, String> fields(String json) {
        Map<String, String> fields = new LinkedHashMap<>();
        Matcher m = Pattern.compile("\"([^\"]+)\":\"((?:[^\"\\\\]++|\\\\.)*+)\"").matcher(json);
        while (m.find()) {
            fields.put(m.group(1), m.group(2).replace("\\\"", "\"").replace("\\\\", "\\"));
        }
        return fields;
    }

    private static String b64(String encoded) {
        return new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------- AWS IAM --

    /** SigV4, written from AWS's specification with the JDK's crypto - for comparing only. */
    private static String expectedSignature(Map<String, String> headers, String body,
            String region) throws Exception {
        TreeMap<String, String> canonical = new TreeMap<>();
        for (Map.Entry<String, String> header : headers.entrySet()) {
            if (!header.getKey().equalsIgnoreCase("Authorization")) {
                canonical.put(header.getKey().toLowerCase(Locale.ROOT), header.getValue().trim());
            }
        }
        StringBuilder request = new StringBuilder("POST\n/\n\n");
        canonical.forEach((name, value) -> request.append(name).append(':').append(value)
                .append('\n'));
        String signed = String.join(";", canonical.keySet());
        request.append('\n').append(signed).append('\n').append(sha256(body));
        String date = headers.get("X-Amz-Date");
        String day = date.substring(0, 8);
        String scope = day + "/" + region + "/sts/aws4_request";
        String toSign = "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n"
                + sha256(request.toString());
        byte[] key = hmac(("AWS4" + SECRET_KEY).getBytes(StandardCharsets.UTF_8), day);
        key = hmac(key, region);
        key = hmac(key, "sts");
        key = hmac(key, "aws4_request");
        return "AWS4-HMAC-SHA256 Credential=" + KEY_ID + "/" + scope + ", SignedHeaders="
                + signed + ", Signature=" + HexFormat.of().formatHex(hmac(key, toSign));
    }

    private static byte[] hmac(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256(String text) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(text.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void anAwsLoginSendsAGetCallerIdentityAwsWouldAccept() throws Exception {
        String sessionToken = "IQoJb3JpZ2luX2VjEXAMPLE/session+token==";
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/aws/login", 200, login("hvs.aws"));
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = VaultLogin.aws(vault.address(), null, "app",
                     VaultLoginBody.AwsIam.Credentials.of(KEY_ID, fixed(SECRET_KEY),
                             fixed(sessionToken)),
                     null, null, "vault.example.com", null, false, 10_000,
                     Clock.fixed(NOW, ZoneOffset.UTC))) {

            assertEquals("hvs.aws", read(login));

            Map<String, String> body = fields(vault.requests().get(0).body());
            assertEquals("app", body.get("role"));
            assertEquals("POST", body.get("iam_http_request_method"));
            assertEquals("https://sts.amazonaws.com/", b64(body.get("iam_request_url")));
            assertEquals("Action=GetCallerIdentity&Version=2011-06-15",
                    b64(body.get("iam_request_body")));

            Map<String, String> headers = fields(b64(body.get("iam_request_headers")));
            assertEquals("sts.amazonaws.com", headers.get("Host"));
            assertEquals("20261029T081530Z", headers.get("X-Amz-Date"));
            assertEquals(sessionToken, headers.get("X-Amz-Security-Token"));
            assertEquals("vault.example.com", headers.get("X-Vault-AWS-IAM-Server-ID"));
            assertEquals(expectedSignature(headers,
                    "Action=GetCallerIdentity&Version=2011-06-15", "us-east-1"),
                    headers.get("Authorization"), "AWS would not accept this signature");
        }
    }

    /** A regional endpoint and a long-term key: no token header, the region in the scope. */
    @Test
    void aRegionalEndpointWithALongTermKey() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/aws-prod/login", 200, login("hvs.aws2"));
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = VaultLogin.aws(vault.address(), "aws-prod", null,
                     VaultLoginBody.AwsIam.Credentials.of(KEY_ID, fixed(SECRET_KEY), null),
                     "sts.eu-central-1.amazonaws.com", "eu-central-1", null, null, false,
                     10_000, Clock.fixed(NOW, ZoneOffset.UTC))) {
            read(login);
            Map<String, String> body = fields(vault.requests().get(0).body());
            assertNull(body.get("role"), "a role was named although none was configured");
            Map<String, String> headers = fields(b64(body.get("iam_request_headers")));
            assertNull(headers.get("X-Amz-Security-Token"));
            assertNull(headers.get("X-Vault-AWS-IAM-Server-ID"));
            assertEquals(expectedSignature(headers,
                    "Action=GetCallerIdentity&Version=2011-06-15", "eu-central-1"),
                    headers.get("Authorization"));
        }
    }

    /** Every login signs anew - a replayed signature is fifteen minutes old at most. */
    @Test
    void eachLoginIsSignedAnew() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/aws/login", 200,
                        "{\"auth\":{\"client_token\":\"hvs.a\",\"lease_duration\":60,"
                                + "\"renewable\":false}}",
                        "{\"auth\":{\"client_token\":\"hvs.b\",\"lease_duration\":60,"
                                + "\"renewable\":false}}");
        Instant[] now = {NOW};
        Clock clock = new Clock() {
            @Override
            public java.time.ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(java.time.ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return now[0];
            }
        };
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = VaultLogin.aws(vault.address(), null, "app",
                     VaultLoginBody.AwsIam.Credentials.of(KEY_ID, fixed(SECRET_KEY), null),
                     null, null, null, null, false, 10_000, clock)) {
            assertEquals("hvs.a", read(login));
            now[0] = NOW.plusSeconds(45);
            assertEquals("hvs.b", read(login));
            List<FakeVaultServer.Request> logins = vault.requests("POST", "/v1/auth/aws/login");
            assertEquals(2, logins.size());
            String first = fields(b64(fields(logins.get(0).body()).get("iam_request_headers")))
                    .get("X-Amz-Date");
            String second = fields(b64(fields(logins.get(1).body()).get("iam_request_headers")))
                    .get("X-Amz-Date");
            assertEquals("20261029T081530Z", first);
            assertEquals("20261029T081615Z", second);
        }
    }

    @Test
    void aRefusedAwsLoginSaysWhatToCheck() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/aws/login", 400, "{\"errors\":[\"entry for role not found\"]}");
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = VaultLogin.aws(vault.address(), null, null,
                     VaultLoginBody.AwsIam.Credentials.of(KEY_ID, fixed(SECRET_KEY), null),
                     null, null, null, null, false, 10_000, Clock.systemUTC())) {
            SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                    () -> read(login));
            assertTrue(refused.getMessage().contains("named after this IAM principal")
                    && refused.getMessage().contains("iam_server_id_header_value"),
                    refused.getMessage());
            assertFalse(refused.getMessage().contains(SECRET_KEY));
        }
    }

    // ------------------------------------------------------- GCP and Azure --

    /** A metadata service on loopback over plain HTTP, as the real ones are link-local. */
    private static final class Metadata implements AutoCloseable {
        final ServerSocket socket;
        final List<String> requests = new CopyOnWriteArrayList<>();
        final Map<String, String> answers;
        final Thread thread;

        Metadata(Map<String, String> answers) throws IOException {
            this.answers = answers;
            this.socket = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
            this.thread = new Thread(this::serve, "fake-metadata");
            this.thread.setDaemon(true);
            this.thread.start();
        }

        private void serve() {
            while (!socket.isClosed()) {
                try (Socket accepted = socket.accept()) {
                    InputStream in = accepted.getInputStream();
                    ByteArrayOutputStream head = new ByteArrayOutputStream();
                    int b;
                    while ((b = in.read()) >= 0) {
                        head.write(b);
                        String seen = head.toString(StandardCharsets.US_ASCII);
                        if (seen.endsWith("\r\n\r\n")) {
                            break;
                        }
                    }
                    String request = head.toString(StandardCharsets.US_ASCII);
                    requests.add(request);
                    String path = request.split(" ")[1];
                    String body = answers.get(path);
                    int status = body == null ? 404 : 200;
                    byte[] bytes = (body == null ? "" : body).getBytes(StandardCharsets.UTF_8);
                    OutputStream out = accepted.getOutputStream();
                    out.write(("HTTP/1.1 " + status + " \r\nContent-Length: " + bytes.length
                            + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    out.write(bytes);
                    out.flush();
                } catch (IOException closedOrFailed) {
                    // next, or the end
                }
            }
        }

        int port() {
            return socket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    private static final String IDENTITY_JWT =
            "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwOi8vdmF1bHQvYXBwIn0.c2lnbmF0dXJl";

    @Test
    void aGcpLoginSendsTheVmsFullIdentityToken() throws Exception {
        String identity = "/computeMetadata/v1/instance/service-accounts/default/identity"
                + "?audience=http%3A%2F%2Fvault%2Fapp&format=full";
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/gcp/login", 200, login("hvs.gcp"));
        try (Metadata metadata = new Metadata(Map.of(identity, IDENTITY_JWT + "\n"));
             FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = VaultLogin.gcp(vault.address(), null, "app",
                     GcpMetadataSecretProvider.fullIdentity("127.0.0.1", metadata.port(), null,
                             VaultLogin.gcpAudience("app", null), 16_384),
                     null, false, 10_000, Clock.systemUTC())) {
            assertEquals("hvs.gcp", read(login));
            assertTrue(metadata.requests.get(0).startsWith("GET " + identity + " "),
                    metadata.requests.get(0));
            assertTrue(metadata.requests.get(0).contains("Metadata-Flavor: Google"));
            assertEquals("{\"role\":\"app\",\"jwt\":\"" + IDENTITY_JWT + "\"}",
                    vault.requests().get(0).body());
        }
    }

    @Test
    void anAzureLoginReadsTheTokenAndWhereTheMachineLivesOnce() throws Exception {
        String tokenPath = "/metadata/identity/oauth2/token?api-version=2018-02-01"
                + "&resource=https%3A%2F%2Fmanagement.azure.com%2F";
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/azure/login", 200,
                        "{\"auth\":{\"client_token\":\"hvs.az1\",\"lease_duration\":60,"
                                + "\"renewable\":false}}",
                        "{\"auth\":{\"client_token\":\"hvs.az2\",\"lease_duration\":60,"
                                + "\"renewable\":false}}");
        Instant[] now = {NOW};
        Clock clock = new Clock() {
            @Override
            public java.time.ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(java.time.ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return now[0];
            }
        };
        try (Metadata imds = new Metadata(Map.of(
                     tokenPath, "{\"access_token\":\"" + IDENTITY_JWT + "\",\"expires_in\":\"3599\"}",
                     VaultLoginBody.AzureVm.COMPUTE_PATH, "{\"subscriptionId\":\"sub-1\","
                             + "\"resourceGroupName\":\"rg-app\",\"name\":\"vm-7\","
                             + "\"vmScaleSetName\":\"\",\"location\":\"westeurope\"}"));
             FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = VaultLogin.azure(vault.address(), null, "app",
                     new AzureManagedIdentitySecretProvider("127.0.0.1", imds.port(), 5_000,
                             "https://management.azure.com/", null, 16_384),
                     VaultLogin.azureVm(null, null, null, null, "127.0.0.1", imds.port()),
                     null, false, 10_000, clock)) {
            assertEquals("hvs.az1", read(login));
            assertEquals("{\"role\":\"app\",\"jwt\":\"" + IDENTITY_JWT + "\","
                    + "\"subscription_id\":\"sub-1\",\"resource_group_name\":\"rg-app\","
                    + "\"vm_name\":\"vm-7\"}", vault.requests().get(0).body());
            now[0] = NOW.plusSeconds(45);
            assertEquals("hvs.az2", read(login));
            long computeAsks = imds.requests.stream()
                    .filter(r -> r.startsWith("GET " + VaultLoginBody.AzureVm.COMPUTE_PATH))
                    .count();
            assertEquals(1, computeAsks, "where the machine lives does not change");
            assertTrue(imds.requests.stream().allMatch(r -> r.contains("Metadata: true")));
        }
    }

    @Test
    void aScaleSetIsNamedAsOneAndConfiguredValuesNeedNoMetadata() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/azure/login", 200, login("hvs.az"));
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = VaultLogin.azure(vault.address(), null, "app",
                     fixed(IDENTITY_JWT),
                     VaultLogin.azureVm("sub-2", "rg-2", null, "vmss-web", "127.0.0.1", 1),
                     null, false, 10_000, Clock.systemUTC())) {
            read(login);
            assertEquals("{\"role\":\"app\",\"jwt\":\"" + IDENTITY_JWT + "\","
                    + "\"subscription_id\":\"sub-2\",\"resource_group_name\":\"rg-2\","
                    + "\"vmss_name\":\"vmss-web\"}", vault.requests().get(0).body());
        }
    }

    // ------------------------------------------------------- configuration --

    private static Map<String, String> vault(String address, String... pairs) {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "vault");
        settings.put("address", address);
        settings.put("path", "secret/data/app");
        if (pairs.length % 2 != 0) {
            throw new IllegalArgumentException("settings come in pairs");
        }
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            settings.put(pairs[i], pairs[i + 1]);
        }
        return settings;
    }

    /** The registry: an AWS key pair from files, and the Vault's verify=false kept to the Vault. */
    @Test
    void theRegistryBuildsAnAwsLoginFromFiles(@TempDir Path directory) throws Exception {
        Path key = Files.writeString(directory.resolve("aws-key"), SECRET_KEY + "\n");
        Path token = Files.writeString(directory.resolve("aws-token"), "FwoGZXIvYXdzEXAMPLE\n");
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/aws/login", 200, login("hvs.reg"))
                .on("GET", "/v1/secret/data/app", 200,
                        "{\"data\":{\"data\":{\"password\":\"hunter2\"}}}");
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             SecretProvider provider = SecretProviders.of(vault(vault.address(),
                     "verify", "false", "auth-method", "aws", "auth-role", "app",
                     "aws-access-key-id", KEY_ID,
                     "aws-key-provider", "file", "aws-key-path", key.toString(),
                     "aws-session-token-provider", "file",
                     "aws-session-token-path", token.toString(),
                     "aws-iam-server-id", "vault.example.com"))) {
            assertEquals("hunter2", read(provider));
            Map<String, String> headers = fields(b64(fields(
                    vault.requests("POST", "/v1/auth/aws/login").get(0).body())
                    .get("iam_request_headers")));
            assertEquals("FwoGZXIvYXdzEXAMPLE", headers.get("X-Amz-Security-Token"),
                    "the token file's line break went into the header");
            assertEquals("vault.example.com", headers.get("X-Vault-AWS-IAM-Server-ID"));
            assertEquals("hvs.reg", vault.requests("GET", "/v1/secret/data/app").get(0)
                    .header("X-Vault-Token"));
        }
    }

    @Test
    void cloudMisconfigurationsAreRefusedAtTheStart() {
        String address = "https://127.0.0.1:8200";
        IllegalArgumentException noAws = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(vault(address, "auth-method", "aws")));
        assertTrue(noAws.getMessage().contains("aws-credentials=instance"), noAws.getMessage());

        IllegalArgumentException noRole = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(vault(address, "auth-method", "gcp")));
        assertTrue(noRole.getMessage().contains("auth-role"), noRole.getMessage());

        IllegalArgumentException partial = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(vault(address, "auth-method", "azure",
                        "auth-role", "app", "azure-subscription-id", "sub")));
        assertTrue(partial.getMessage().contains("together"), partial.getMessage());

        IllegalArgumentException badServerId = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(vault(address, "auth-method", "aws",
                        "aws-access-key-id", KEY_ID, "aws-key-provider", "file",
                        "aws-key-path", "/x", "aws-iam-server-id", "a\r\nb")));
        assertTrue(badServerId.getMessage().contains("printable ASCII"),
                badServerId.getMessage());

        IllegalArgumentException viaCredential = assertThrows(IllegalArgumentException.class,
                () -> new VaultLogin(address, VaultLogin.Method.AWS, null, "app", fixed("x"),
                        null, true, 1000));
        assertTrue(viaCredential.getMessage().contains("VaultLogin.aws"),
                viaCredential.getMessage());
    }
}
