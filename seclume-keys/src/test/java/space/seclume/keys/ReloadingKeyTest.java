package space.seclume.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A renewed server key and certificate, taken up by the next handshake - and a
 * renewal that is only half there, refused while the old pair keeps serving.
 */
class ReloadingKeyTest {

    @TempDir
    Path directory;

    @org.junit.jupiter.api.BeforeEach
    void needsOpenSsl() {
        assumeTrue(space.seclume.crypto.OpenSslSigningKey.available(), "OpenSSL 3 on 64-bit Linux");
    }

    private static void put(Path from, Path to) throws Exception {
        Path next = to.resolveSibling(to.getFileName() + ".next");
        Files.copy(from, next, StandardCopyOption.REPLACE_EXISTING);
        Files.move(next, to, StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);
    }

    @Test
    void aRenewedPairIsServedWithoutARestart() throws Exception {
        KeyFiles first = KeyFiles.make(directory.resolve("first"), "ec:P-256");
        KeyFiles second = KeyFiles.make(directory.resolve("second"), "ec:P-256");
        Path live = Files.createDirectory(directory.resolve("live"));
        Path key = live.resolve("tls.key");
        Path chain = live.resolve("tls.crt");
        put(first.key(), key);
        put(first.certificate(), chain);

        ReloadingKeyManager manager = (ReloadingKeyManager) SeclumeKeys.keyManager(chain,
                "provider=file&path=" + key, Duration.ofHours(1));
        try (manager) {
            SSLContext server = SSLContext.getInstance("TLSv1.3");
            server.init(new KeyManager[] {manager}, null, null);
            assertEquals("hello", ServerKeyTest.roundTrip(server, first, "TLSv1.3", null));

            // half a renewal: the new key, the old certificate - refused, the old pair serves
            put(second.key(), key);
            manager.checkNow();
            assertEquals(1, manager.generations(), "a key without its certificate was taken");
            assertEquals("hello", ServerKeyTest.roundTrip(server, first, "TLSv1.3", null));

            // the other half: now the new pair is served
            put(second.certificate(), chain);
            manager.checkNow();
            assertEquals(2, manager.generations());
            assertEquals("hello", ServerKeyTest.roundTrip(server, second, "TLSv1.3", null));
            assertThrows(SSLException.class,
                    () -> ServerKeyTest.roundTrip(server, first, "TLSv1.3", null),
                    "the old certificate is still served");
        }
    }

    @Test
    void theWatchFindsARenewalOnItsOwn() throws Exception {
        KeyFiles first = KeyFiles.make(directory.resolve("a"), "rsa:2048");
        KeyFiles second = KeyFiles.make(directory.resolve("b"), "rsa:2048");
        Path live = Files.createDirectory(directory.resolve("live"));
        Path key = live.resolve("tls.key");
        Path chain = live.resolve("tls.crt");
        put(first.key(), key);
        put(first.certificate(), chain);
        ReloadingKeyManager manager = (ReloadingKeyManager) SeclumeKeys.keyManager(chain,
                "provider=file&path=" + key, Duration.ofMillis(50));
        try (manager) {
            SSLContext server = SSLContext.getInstance("TLSv1.3");
            server.init(new KeyManager[] {manager}, null, null);
            put(second.key(), key);
            put(second.certificate(), chain);
            long deadline = System.nanoTime() + 10_000_000_000L;
            while (manager.generations() < 2 && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            assertTrue(manager.generations() >= 2, "the renewal was never taken up");
            assertEquals("hello", ServerKeyTest.roundTrip(server, second, "TLSv1.3", null));
        }
    }
}
