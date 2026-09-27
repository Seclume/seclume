package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * SecretFetch's HTTP response reading against a server that lies: chunk sizes
 * that overflow, bodies shorter than announced. Driven through the plain
 * loopback path, which reads responses exactly as the TLS path does.
 *
 * <p>The bodies are public filler; nothing here is a secret.
 */
@Timeout(30)
class SecretFetchRegressionTest {

    /** Answers one request with {@code response}, then closes. */
    private static int serveOnce(String response) throws IOException {
        ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        Thread.ofPlatform().daemon().start(() -> {
            try (server; Socket socket = server.accept()) {
                InputStream in = socket.getInputStream();
                byte[] buffer = new byte[8192];
                int seen = 0;
                // Read up to the end of the request head.
                while (true) {
                    int read = in.read(buffer, seen, buffer.length - seen);
                    if (read < 0) {
                        return;
                    }
                    seen += read;
                    if (new String(buffer, 0, seen, StandardCharsets.ISO_8859_1)
                            .contains("\r\n\r\n")) {
                        break;
                    }
                }
                OutputStream out = socket.getOutputStream();
                out.write(response.getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
            } catch (IOException ignored) {
                // the test decides from the client's side
            }
        });
        return server.getLocalPort();
    }

    private static SecretFetch.Response fetch(String response) throws IOException {
        int port = serveOnce(response);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment body = arena.allocate(1024);
            return SecretFetch.sendLinkLocal("127.0.0.1", port, 5000, "GET", "/", Map.of(), body);
        }
    }

    @Test
    void aWellFormedChunkedBodyIsRead() throws IOException {
        SecretFetch.Response response = fetch("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                + "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        assertEquals(200, response.status());
        assertEquals(11, response.bodyLength());
    }

    /**
     * {@code fffffff4} is -12 as an int. The parser used to step backwards
     * over the same header and loop, with a negative body length.
     */
    @Test
    void aChunkSizeThatOverflowsIsRefused() {
        IOException refused = assertThrows(IOException.class, () -> fetch(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                        + "fffffff4\r\nx\r\n0\r\n\r\n"));
        assertTrue(refused.getMessage().contains("chunk"), refused.getMessage());
    }

    @Test
    void aChunkSizeWithoutDigitsIsRefused() {
        assertThrows(IOException.class, () -> fetch(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                        + "zz\r\nx\r\n0\r\n\r\n"));
    }

    @Test
    void aChunkLargerThanTheBodyMayBeIsRefused() {
        assertThrows(IOException.class, () -> fetch(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                        + "7fffffff\r\nx\r\n0\r\n\r\n"));
    }

    @Test
    void aBodyShorterThanItsContentLengthIsRefused() {
        IOException refused = assertThrows(IOException.class, () -> fetch(
                "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + "0123456789"));
        assertTrue(refused.getMessage().contains("100"), refused.getMessage());
    }

    @Test
    void aBodyLongerThanItsContentLengthIsCutToIt() throws IOException {
        SecretFetch.Response response = fetch(
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n" + "0123456789");
        assertEquals(4, response.bodyLength());
    }

    @Test
    void aMalformedContentLengthReadsToTheEnd() throws IOException {
        SecretFetch.Response response = fetch(
                "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n" + "abc");
        assertEquals(3, response.bodyLength());
    }

    @Test
    void aResponseWithoutAHeadIsRefused() {
        assertThrows(IOException.class, () -> fetch("HTTP/1.1 200 OK\r\nContent-Len"));
    }

    @Test
    void aSecretHeaderThatDoesNotFitFailsBeforeAnythingIsSent() throws IOException {
        ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        try (server; Arena arena = Arena.ofConfined()) {
            MemorySegment value = arena.allocate(16 * 1024).fill((byte) 'z');
            assertThrows(java.nio.BufferOverflowException.class, () -> SecretFetch.sendLinkLocal(
                    "127.0.0.1", server.getLocalPort(), 2000, "GET", "/", Map.of(),
                    java.util.List.of(new SecretFetch.SecretHeader("X-Token", value,
                            (int) value.byteSize())),
                    arena.allocate(64)));
        }
    }
}
