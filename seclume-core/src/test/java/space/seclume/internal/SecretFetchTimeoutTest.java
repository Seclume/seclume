package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A secret manager or metadata service that takes the connection and then
 * says nothing - or a byte at a time. The timeout a provider gives used to be
 * the connect's only: the handshake and the answer waited for ever, and every
 * login waiting for the secret with them.
 */
@Timeout(60)
class SecretFetchTimeoutTest {

    /** Takes connections and holds them, silent - or sends {@code dribble} a byte every 700 ms. */
    private static ServerSocket server(byte[] dribble) throws IOException {
        ServerSocket listener = new ServerSocket(0, 4, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            while (!listener.isClosed()) {
                try {
                    Socket client = listener.accept();
                    Thread.ofVirtual().start(() -> {
                        try (client) {
                            client.getInputStream().read(new byte[4096]);
                            OutputStream out = client.getOutputStream();
                            if (dribble == null) {
                                Thread.sleep(60_000);
                            }
                            for (int i = 0; dribble != null && i < 100_000; i++) {
                                out.write(dribble[Math.min(i, dribble.length - 1)]);
                                out.flush();
                                Thread.sleep(700);
                            }
                        } catch (IOException | InterruptedException gone) {
                            // the client gave up - what the test wants
                        }
                    });
                } catch (IOException closed) {
                    return;
                }
            }
        });
        return listener;
    }

    private static void inTime(long started, long limitMillis) {
        long took = (System.nanoTime() - started) / 1_000_000;
        assertTrue(took < limitMillis, "it took " + took + " ms");
    }

    @Test
    void aSilentSecretManagerIsGivenUpOnAfterTheTimeout() throws Exception {
        try (ServerSocket silent = server(null)) {
            long started = System.nanoTime();
            assertThrows(SocketTimeoutException.class, () -> SecretFetch.send("127.0.0.1",
                    silent.getLocalPort(), true, 1000, "GET", "/v1/secret/x", Map.of(), List.of(),
                    null, null));
            inTime(started, 8000);
        }
    }

    @Test
    void aSilentMetadataServiceIsGivenUpOnAfterTheTimeout() throws Exception {
        try (ServerSocket silent = server(null)) {
            long started = System.nanoTime();
            assertThrows(SocketTimeoutException.class, () -> SecretFetch.sendLinkLocal(
                    "127.0.0.1", silent.getLocalPort(), 1000, "GET", "/metadata", Map.of(), null));
            inTime(started, 8000);
        }
    }

    @Test
    void aDribblingAnswerIsGivenUpOnWithinTheBudget() throws Exception {
        // A TLS record header announcing 16 KiB of handshake, then a byte at a time.
        try (ServerSocket slow = server(new byte[] {0x16, 0x03, 0x03, 0x40, 0x00, 0x02})) {
            long started = System.nanoTime();
            SocketTimeoutException late = assertThrows(SocketTimeoutException.class,
                    () -> SecretFetch.send("127.0.0.1", slow.getLocalPort(), true, 1000, "GET",
                            "/v1/secret/x", Map.of(), List.of(), null, null));
            assertTrue(late.getMessage().contains("did not answer within 3 s"), late.toString());
            inTime(started, 10_000);
        }
        // HTTP headers that never end, over the metadata service's plain HTTP.
        try (ServerSocket slow = server("HTTP/1.1 200 OK\r\nX-Padding: x".getBytes(
                java.nio.charset.StandardCharsets.US_ASCII))) {
            long started = System.nanoTime();
            assertThrows(SocketTimeoutException.class, () -> SecretFetch.sendLinkLocal(
                    "127.0.0.1", slow.getLocalPort(), 1000, "GET", "/metadata", Map.of(), null));
            inTime(started, 30_000);
        }
    }

    @Test
    void theBudgetIsTheTimeoutTimesTheFactor() {
        assertEquals(0, SecretFetch.budget(0));
        assertEquals(3, SecretFetch.budget(1000));
        assertEquals(1, SecretFetch.budget(1));
    }
}
