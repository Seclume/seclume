package space.seclume.redis;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import redis.clients.jedis.exceptions.JedisConnectionException;

/**
 * A server that takes the connection and says nothing. The read timeout was
 * set after the TLS handshake, so a {@code rediss://} handshake with it - and
 * Jedis's {@code createSocket} - waited for ever.
 */
@Timeout(60)
class SilentServerTest {

    @Test
    @SuppressWarnings("try") // the accepted socket is held open, never used
    void aSilentServerIsGivenUpOnAfterTheTimeout() throws Exception {
        Path secret = Files.createTempFile("redis", ".pw");
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Files.writeString(secret, "never-sent");
            Thread.ofVirtual().start(() -> {
                try (Socket client = silent.accept()) {
                    Thread.sleep(60_000);
                } catch (IOException | InterruptedException gone) {
                    // the client gave up - what the test wants
                }
            });
            SeclumeRedisSocketFactory sockets = SeclumeRedisSocketFactory.of("rediss://127.0.0.1:"
                    + silent.getLocalPort() + "?provider=file&path="
                    + secret.toString().replace('\\', '/') + "&timeout=1000&connectTimeout=1000");
            long started = System.nanoTime();
            assertThrows(JedisConnectionException.class, sockets::createSocket);
            long took = (System.nanoTime() - started) / 1_000_000;
            assertTrue(took < 8000, "the handshake took " + took + " ms");
        } finally {
            Files.deleteIfExists(secret);
        }
    }
}
