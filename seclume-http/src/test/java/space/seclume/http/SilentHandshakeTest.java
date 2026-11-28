package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * {@code createSocket(host, port)} makes the TCP connection itself, and so
 * the handshake's time limit is its own too: a server that takes the
 * connection and says nothing used to hold the handshake for good -
 * {@code connectTimeout} bounded the connect only.
 */
@Timeout(60)
@SuppressWarnings("try") // the accepted sockets are held open, never used
class SilentHandshakeTest {

    @Test
    void aSilentServerIsGivenUpOnWithinTheConnectTimeout() throws Exception {
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread.ofVirtual().start(() -> {
                try (Socket client = silent.accept()) {
                    Thread.sleep(60_000);
                } catch (IOException | InterruptedException gone) {
                    // the client gave up - what the test wants
                }
            });
            SeclumeSslSocketFactory sockets = SeclumeSslSocketFactory.of("connectTimeout=1000");
            long started = System.nanoTime();
            assertThrows(IOException.class, () -> sockets.createSocket("127.0.0.1",
                    silent.getLocalPort()));
            long took = (System.nanoTime() - started) / 1_000_000;
            assertTrue(took < 8000, "the handshake took " + took + " ms");
        }
    }

    @Test
    void aLayeredSocketKeepsTheTimeoutItsCallerSet() throws Exception {
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread.ofVirtual().start(() -> {
                try (Socket client = silent.accept()) {
                    Thread.sleep(60_000);
                } catch (IOException | InterruptedException gone) {
                    // the client gave up - what the test wants
                }
            });
            Socket plain = new Socket(InetAddress.getLoopbackAddress(), silent.getLocalPort());
            plain.setSoTimeout(1000);
            long started = System.nanoTime();
            assertThrows(IOException.class, () -> SeclumeSslSocketFactory.of("")
                    .createSocket(plain, "127.0.0.1", silent.getLocalPort(), true));
            assertEquals(true, (System.nanoTime() - started) / 1_000_000 < 8000);
        }
    }
}
