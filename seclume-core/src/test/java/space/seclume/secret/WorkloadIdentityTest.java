package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Workload identity: the token comes from the machine, not from a store.
 *
 * <p>Against a stand-in for the metadata service on loopback - which is the
 * one other address the plain-HTTP path accepts, because it is the same
 * machine. What is checked is the part that decides whether a real IMDS or
 * metadata server would answer at all: the path, the query, and the guard
 * header each of them insists on; then that the token lands in the target
 * and nowhere else, and that a failure says what it means without quoting the
 * answer.
 */
@Timeout(60)
@org.junit.jupiter.api.parallel.Isolated
class WorkloadIdentityTest {

    /** Shaped like a real token and unmistakable, so a leak into a message would be seen. */
    private static final String TOKEN = "eyJ0eXAiOiJKV1QifQ.wl-identity-token-5c1e.sig";

    /** One request, one canned answer, and the request kept for inspection. */
    private static final class Metadata implements AutoCloseable {

        private final ServerSocket socket;
        private final Thread thread;
        private volatile String request = "";

        Metadata(int status, String body) throws IOException {
            socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
            thread = Thread.ofVirtual().start(() -> {
                try (Socket client = socket.accept()) {
                    request = readHead(client.getInputStream());
                    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                    OutputStream out = client.getOutputStream();
                    out.write(("HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\n"
                            + "Content-Length: " + bytes.length + "\r\n\r\n")
                            .getBytes(StandardCharsets.US_ASCII));
                    out.write(bytes);
                    out.flush();
                } catch (IOException closed) {
                    // The test is over.
                }
            });
        }

        int port() {
            return socket.getLocalPort();
        }

        private static String readHead(InputStream in) throws IOException {
            StringBuilder head = new StringBuilder();
            int c;
            while ((c = in.read()) >= 0) {
                head.append((char) c);
                if (head.toString().endsWith("\r\n\r\n")) {
                    break;
                }
            }
            return head.toString();
        }

        @Override
        public void close() throws IOException {
            socket.close();
            try {
                thread.join(2000);
            } catch (InterruptedException stop) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Test
    void azureAsksImdsTheWayImdsInsistsOn() throws Exception {
        String answer = "{\"access_token\":\"" + TOKEN + "\",\"expires_in\":\"3599\","
                + "\"expires_on\":\"1790000000\",\"resource\":\"x\",\"token_type\":\"Bearer\"}";
        try (Metadata imds = new Metadata(200, answer)) {
            SecretProvider provider = new AzureManagedIdentitySecretProvider("127.0.0.1",
                    imds.port(), 5_000, AzureManagedIdentitySecretProvider.OSSRDBMS_RESOURCE,
                    "3f1c-client", 8192);
            assertEquals(TOKEN, read(provider));

            String request = imds.request;
            assertTrue(request.startsWith("GET /metadata/identity/oauth2/token?api-version="),
                    request);
            assertTrue(request.contains(
                    "resource=https%3A%2F%2Fossrdbms-aad.database.windows.net"), request);
            assertTrue(request.contains("&client_id=3f1c-client"), request);
            assertTrue(request.contains("\r\nMetadata: true\r\n"),
                    "IMDS refuses a request without this header: " + request);
        }
    }

    @Test
    void googleAsksTheMetadataServerTheWayItInsistsOn() throws Exception {
        String answer = "{\"access_token\":\"" + TOKEN + "\",\"expires_in\":3599,"
                + "\"token_type\":\"Bearer\"}";
        try (Metadata server = new Metadata(200, answer)) {
            SecretProvider provider = new GcpMetadataSecretProvider("127.0.0.1", server.port(),
                    5_000, null, null, 8192);
            assertEquals(TOKEN, read(provider));

            String request = server.request;
            assertTrue(request.startsWith(
                    "GET /computeMetadata/v1/instance/service-accounts/default/token "), request);
            assertTrue(request.contains("\r\nMetadata-Flavor: Google\r\n"),
                    "the metadata server refuses a request without this header: " + request);
        }
    }

    /**
     * A refusal says what it means - and does not quote the answer.
     *
     * <p>An error document from a token endpoint is not a place to go
     * looking for what is in it, and a message is copied into logs.
     */
    @Test
    void aRefusalIsExplainedWithoutQuotingTheAnswer() throws Exception {
        try (Metadata imds = new Metadata(400, "{\"error\":\"" + TOKEN + "\"}")) {
            SecretProvider provider = new AzureManagedIdentitySecretProvider("127.0.0.1",
                    imds.port(), 5_000, AzureManagedIdentitySecretProvider.OSSRDBMS_RESOURCE,
                    null, 8192);
            SecretUnavailableException refused =
                    assertThrows(SecretUnavailableException.class, () -> read(provider));
            assertTrue(refused.getMessage().contains("400"), refused.getMessage());
            assertTrue(refused.getMessage().contains("no identity is assigned"),
                    refused.getMessage());
            assertFalse(refused.getMessage().contains(TOKEN),
                    "the answer's body reached the message");
        }
    }

    /**
     * Plain HTTP is for the metadata address and nothing else.
     *
     * <p>A configuration that points one of these at a real host by mistake
     * has to fail, not work: a token fetched in clear across a network is a
     * token given away. The address is refused before anything is sent.
     */
    @Test
    void plainHttpToAnyOtherAddressIsRefused() {
        SecretProvider elsewhere = new GcpMetadataSecretProvider("192.0.2.10", 80, 2_000,
                null, null, 8192);
        SecretUnavailableException refused =
                assertThrows(SecretUnavailableException.class, () -> read(elsewhere));
        assertTrue(refused.getMessage().contains("refusing plain HTTP"), refused.getMessage());
    }

    /** A token longer than the bound fails cleanly and says what to change. */
    @Test
    void aTokenPastTheBoundSaysSo() throws Exception {
        try (Metadata imds = new Metadata(200, "{\"access_token\":\"" + TOKEN + "\"}")) {
            SecretProvider tooSmall = new AzureManagedIdentitySecretProvider("127.0.0.1",
                    imds.port(), 5_000, AzureManagedIdentitySecretProvider.OSSRDBMS_RESOURCE,
                    null, 16);
            SecretUnavailableException refused =
                    assertThrows(SecretUnavailableException.class, () -> read(tooSmall));
            assertTrue(refused.getMessage().contains("max-length"), refused.getMessage());
        }
    }

    /** Configured the way a URL or Spring configures it. */
    @Test
    void theRegistryBuildsBothWithRoomForAToken() {
        SecretProvider azure = SecretProviders.of(Map.of(
                "provider", "azure-managed-identity",
                "resource", AzureManagedIdentitySecretProvider.OSSRDBMS_RESOURCE));
        assertInstanceOf(AzureManagedIdentitySecretProvider.class, azure);
        assertEquals(8192, azure.maxSecretLength(),
                "an Entra token is around two kilobytes; the password default would refuse it");

        assertInstanceOf(GcpMetadataSecretProvider.class,
                SecretProviders.of(Map.of("provider", "gcp-metadata")));

        IllegalArgumentException missing = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(Map.of("provider", "azure-managed-identity")));
        assertTrue(missing.getMessage().contains("resource"), missing.getMessage());
    }

    /** And as the token source of a secret manager: the machine's identity reads the vault. */
    @Test
    void itServesAsTheTokenOfAKeyVault() {
        SecretProvider vault = SecretProviders.of(Map.of(
                "provider", "azure-key-vault",
                "vault-uri", "https://example.vault.azure.net",
                "name", "db-password",
                "token-provider", "azure-managed-identity",
                "token-resource", "https://vault.azure.net"));
        assertInstanceOf(AzureKeyVaultSecretProvider.class, vault);
    }

    @Test
    void awsInstanceRoleAsksImdsV2InThreeStepsAndSignsRdsIam() throws Exception {
        String credentialsJson = "{\"AccessKeyId\":\"ASIAIOSFODNN7EXAMPLE\","
                + "\"SecretAccessKey\":\"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY\","
                + "\"Token\":\"FwoGZXIvYXdzEImdsSessionToken\","
                + "\"Expiration\":\"" + java.time.Instant.now().plusSeconds(3600) + "\"}";
        List<String> requests = new java.util.concurrent.CopyOnWriteArrayList<>();
        try (ServerSocket server = new ServerSocket(0, 4, InetAddress.getLoopbackAddress())) {
            Thread thread = Thread.ofVirtual().start(() -> {
                String[] answers = {"imds-v2-session-token", "app-role\n", credentialsJson};
                for (String answer : answers) {
                    try (Socket client = server.accept()) {
                        requests.add(Metadata.readHead(client.getInputStream()));
                        byte[] bytes = answer.getBytes(StandardCharsets.UTF_8);
                        OutputStream out = client.getOutputStream();
                        out.write(("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                                + "Content-Length: " + bytes.length + "\r\n\r\n")
                                .getBytes(StandardCharsets.US_ASCII));
                        out.write(bytes);
                        out.flush();
                    } catch (IOException closed) {
                        return;
                    }
                }
            });
            AwsInstanceRole role = new AwsInstanceRole("127.0.0.1", server.getLocalPort(), 5_000);
            try (RdsIamSecretProvider provider = new RdsIamSecretProvider(
                    role, "eu-central-1", "db.example.com", 5432, "app")) {
                String signed = read(provider);
                assertTrue(signed.startsWith("db.example.com:5432/?Action=connect&DBUser=app"),
                        signed);
                assertTrue(signed.contains("ASIAIOSFODNN7EXAMPLE"), signed);
                assertTrue(signed.contains("&X-Amz-Security-Token=FwoGZXIvYXdzEImdsSessionToken&"),
                        signed);
            } finally {
                role.close();
            }
            thread.join(2_000);
        }
        assertEquals(3, requests.size(), requests.toString());
        assertTrue(requests.get(0).startsWith("PUT /latest/api/token "), requests.get(0));
        assertTrue(requests.get(0).contains("X-aws-ec2-metadata-token-ttl-seconds: 300"),
                requests.get(0));
        assertTrue(requests.get(1).startsWith("GET /latest/meta-data/iam/security-credentials/ "),
                requests.get(1));
        assertTrue(requests.get(1).contains("X-aws-ec2-metadata-token: imds-v2-session-token"),
                requests.get(1));
        assertTrue(requests.get(2).startsWith(
                "GET /latest/meta-data/iam/security-credentials/app-role "), requests.get(2));
        assertTrue(requests.get(2).contains("X-aws-ec2-metadata-token: imds-v2-session-token"),
                requests.get(2));
    }

    @Test
    void awsContainerCredentialsFeedRdsIam(
            @org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        java.nio.file.Path tokenFile = dir.resolve("container-token");
        java.nio.file.Files.writeString(tokenFile, "eks-pod-identity-secret-token");
        String credentialsJson = "{\"AccessKeyId\":\"ASIACONTAINEREXAMPLE\","
                + "\"SecretAccessKey\":\"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY\","
                + "\"Token\":\"FwoGZXIvYXdzEContainerSessionToken\","
                + "\"Expiration\":\"" + java.time.Instant.now().plusSeconds(3600) + "\"}";
        long openBefore = SecretScope.open();
        try (Metadata endpoint = new Metadata(200, credentialsJson);
             SecretProvider provider = SecretProviders.of(Map.of(
                     "provider", "rds-iam",
                     "credentials", "container",
                     "container-uri", "http://127.0.0.1:" + endpoint.port() + "/v1/credentials",
                     "container-token-file", tokenFile.toString(),
                     "region", "eu-central-1",
                     "host", "db.example.com",
                     "port", "5432",
                     "user", "app"))) {
            String signed = read(provider);
            assertTrue(signed.contains("ASIACONTAINEREXAMPLE"), signed);
            assertTrue(signed.contains(
                    "&X-Amz-Security-Token=FwoGZXIvYXdzEContainerSessionToken&"), signed);
            assertTrue(endpoint.request.startsWith("GET /v1/credentials "), endpoint.request);
            assertTrue(endpoint.request.contains(
                    "\r\nAuthorization: eks-pod-identity-secret-token\r\n"), endpoint.request);
        }
        assertEquals(openBefore, SecretScope.open());
    }

    @Test
    void awsWebIdentityCredentialsFeedRdsIam(
            @org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(
                space.seclume.tls.TestCertificates.available(), "no keytool in this JDK");
        java.nio.file.Path jwtFile = dir.resolve("web-identity-token");
        java.nio.file.Files.writeString(jwtFile, "eyJhbGciOiJSUzI1NiJ9.irsa-jwt.sig");
        String xml = "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult>"
                + "<Credentials><AccessKeyId>ASIAWEBIDEXAMPLE</AccessKeyId>"
                + "<SecretAccessKey>wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY</SecretAccessKey>"
                + "<SessionToken>FwoGZXIvYXdzEWebIdentitySessionToken</SessionToken>"
                + "<Expiration>" + java.time.Instant.now().plusSeconds(3600) + "</Expiration>"
                + "</Credentials></AssumeRoleWithWebIdentityResult>"
                + "</AssumeRoleWithWebIdentityResponse>";
        long openBefore = SecretScope.open();
        try (space.seclume.tls.TestCertificates certs =
                     space.seclume.tls.TestCertificates.generate()) {
            space.seclume.tls.TestCertificates.Issued issued =
                    certs.issue("sts", "san=ip:127.0.0.1", "eku=serverAuth");
            java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
            try (InputStream in = java.nio.file.Files.newInputStream(issued.keystore())) {
                store.load(in, space.seclume.tls.TestCertificates.PASSWORD.toCharArray());
            }
            javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance(
                    javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(store, space.seclume.tls.TestCertificates.PASSWORD.toCharArray());
            javax.net.ssl.SSLContext ssl = javax.net.ssl.SSLContext.getInstance("TLSv1.3");
            ssl.init(kmf.getKeyManagers(), null, null);

            StringBuilder recorded = new StringBuilder();
            try (javax.net.ssl.SSLServerSocket server = (javax.net.ssl.SSLServerSocket)
                    ssl.getServerSocketFactory().createServerSocket(
                            0, 1, InetAddress.getLoopbackAddress())) {
                Thread thread = Thread.ofVirtual().start(() -> {
                    try (javax.net.ssl.SSLSocket client =
                                 (javax.net.ssl.SSLSocket) server.accept()) {
                        InputStream in = client.getInputStream();
                        String head = Metadata.readHead(in);
                        recorded.append(head);
                        for (String line : head.split("\r\n")) {
                            if (line.toLowerCase(java.util.Locale.ROOT)
                                    .startsWith("content-length:")) {
                                int len = Integer.parseInt(
                                        line.substring(line.indexOf(':') + 1).trim());
                                byte[] body = in.readNBytes(len);
                                recorded.append(new String(body, StandardCharsets.UTF_8));
                            }
                        }
                        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
                        OutputStream out = client.getOutputStream();
                        out.write(("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n"
                                + "Content-Length: " + bytes.length + "\r\n"
                                + "Connection: close\r\n\r\n")
                                .getBytes(StandardCharsets.US_ASCII));
                        out.write(bytes);
                        out.flush();
                    } catch (IOException ignored) {
                    }
                });
                try (SecretProvider provider = SecretProviders.of(Map.of(
                        "provider", "rds-iam",
                        "credentials", "web-identity",
                        "role-arn", "arn:aws:iam::123456789012:role/rds-app",
                        "web-identity-token-file", jwtFile.toString(),
                        "sts-endpoint", "127.0.0.1:" + server.getLocalPort(),
                        "tls-root-cert", issued.keystore().resolveSibling("ca.cer").toString(),
                        "region", "eu-central-1",
                        "host", "db.example.com",
                        "port", "5432",
                        "user", "app"))) {
                    String signed = read(provider);
                    assertTrue(signed.contains("ASIAWEBIDEXAMPLE"), signed);
                    assertTrue(signed.contains(
                            "&X-Amz-Security-Token=FwoGZXIvYXdzEWebIdentitySessionToken&"),
                            signed);
                }
                thread.join(2_000);
            }
            String req = recorded.toString();
            assertTrue(req.contains("Action=AssumeRoleWithWebIdentity"), req);
            assertTrue(req.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Frds-app"),
                    req);
            assertTrue(req.contains("WebIdentityToken=eyJhbGciOiJSUzI1NiJ9.irsa-jwt.sig"), req);
        }
        assertEquals(openBefore, SecretScope.open());
    }

    private static String read(SecretProvider provider) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            int length = provider.writeSecret(target);
            byte[] copy = new byte[length];
            MemorySegment.copy(target, ValueLayout.JAVA_BYTE, 0, copy, 0, length);
            return new String(copy, StandardCharsets.US_ASCII);
        }
    }
}
