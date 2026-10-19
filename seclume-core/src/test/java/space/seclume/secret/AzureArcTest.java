package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Azure Arc's identity endpoint, as its agent behaves: a request without a
 * challenge is answered 401, naming a file in the agent's token directory;
 * the content of that file, as {@code Authorization: Basic ...}, gets the
 * token. A file outside that directory is refused before it is read.
 */
class AzureArcTest {

    private static final String TOKEN = "eyJ0eXAiOiJKV1QifQ.arc-identity-7d2e.sig";

    @TempDir
    Path directory;

    /** The agent: 401 with the realm, then the token for the right challenge. */
    private static final class Agent implements AutoCloseable {
        private final ServerSocket socket;
        private final Thread thread;
        final List<String> requests = new CopyOnWriteArrayList<>();

        Agent(Path realm, String expected) throws IOException {
            socket = new ServerSocket(0, 4, InetAddress.getLoopbackAddress());
            thread = Thread.ofVirtual().start(() -> {
                while (!socket.isClosed()) {
                    try (Socket client = socket.accept()) {
                        String request = head(client.getInputStream());
                        requests.add(request);
                        boolean challenged = request.contains("\r\nAuthorization: Basic "
                                + expected + "\r\n");
                        String body = challenged ? "{\"access_token\":\"" + TOKEN
                                + "\",\"expires_on\":\"1790000000\",\"token_type\":\"Bearer\"}"
                                : "{}";
                        OutputStream out = client.getOutputStream();
                        out.write(((challenged ? "HTTP/1.1 200 OK\r\n"
                                : "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="
                                        + realm + "\r\n")
                                + "Content-Type: application/json\r\nContent-Length: "
                                + body.length() + "\r\n\r\n" + body)
                                .getBytes(StandardCharsets.US_ASCII));
                        out.flush();
                    } catch (IOException closed) {
                        return;
                    }
                }
            });
        }

        int port() {
            return socket.getLocalPort();
        }

        private static String head(InputStream in) throws IOException {
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

    private static String read(SecretProvider provider) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            int length = provider.writeSecret(target);
            return new String(target.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.UTF_8);
        }
    }

    @Test
    void theChallengeFileIsReadAndSentBack() throws Exception {
        Path tokens = Files.createDirectories(directory.resolve("tokens"));
        Path key = tokens.resolve("5b1c9e.key");
        Files.writeString(key, "arc-challenge-0f3a");
        try (Agent agent = new Agent(key, "arc-challenge-0f3a")) {
            SecretProvider arc = AzureManagedIdentitySecretProvider.arc(
                    "http://127.0.0.1:" + agent.port() + "/metadata/identity/oauth2/token",
                    "https://ossrdbms-aad.database.windows.net", tokens, 8192);
            assertEquals(TOKEN, read(arc));
            assertEquals(2, agent.requests.size());
            assertTrue(agent.requests.get(0).startsWith("GET /metadata/identity/oauth2/token"
                    + "?api-version=2020-06-01&resource="), agent.requests.get(0));
            assertTrue(agent.requests.get(0).contains("\r\nMetadata: true\r\n"));
            assertFalse(agent.requests.get(0).contains("Authorization"));
        }
    }

    /** An agent - or something posing as one - that names another file gets nothing read. */
    @Test
    void aFileOutsideTheTokenDirectoryIsRefused() throws Exception {
        Path tokens = Files.createDirectories(directory.resolve("tokens"));
        Path elsewhere = directory.resolve("ssh-private.key");
        Files.writeString(elsewhere, "not for the asking");
        try (Agent agent = new Agent(elsewhere, "not for the asking")) {
            SecretProvider arc = AzureManagedIdentitySecretProvider.arc(
                    "http://127.0.0.1:" + agent.port() + "/metadata/identity/oauth2/token",
                    "https://vault.azure.net", tokens, 8192);
            SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                    () -> read(arc));
            assertTrue(refused.getMessage().contains("outside its token directory"),
                    refused.getMessage());
            assertEquals(1, agent.requests.size(), "the challenge went out anyway");
        }
    }
}
