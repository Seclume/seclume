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
