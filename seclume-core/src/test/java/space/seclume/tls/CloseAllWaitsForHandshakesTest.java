package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * {@link ClientIdentities#closeAll()} closes the keys every cached identity
 * signs with. Its Javadoc said "where no handshake is running" and nothing
 * held it to that: a handshake signing at that moment failed half way. It
 * waits for the running ones now, and gives up with a warning after a while.
 */
// Alone: the count of running handshakes and the cache are the whole JVM's.
@Isolated
@Timeout(30)
class CloseAllWaitsForHandshakesTest {

    @Test
    void closeAllWaitsUntilTheRunningHandshakeIsOver() throws Exception {
        ClientIdentities.handshakeStarted();
        CountDownLatch closed = new CountDownLatch(1);
        Thread closing = Thread.ofVirtual().start(() -> {
            ClientIdentities.closeAll(Duration.ofSeconds(20));
            closed.countDown();
        });
        try {
            assertFalse(closed.await(300, TimeUnit.MILLISECONDS),
                    "closeAll did not wait for the handshake");
        } finally {
            ClientIdentities.handshakeEnded();
        }
        assertTrue(closed.await(5, TimeUnit.SECONDS), "closeAll went on waiting after it ended");
        closing.join();
    }

    @Test
    void aHandshakeThatDoesNotEndIsWaitedForOnlySoLong() throws Exception {
        ClientIdentities.handshakeStarted();
        try {
            long started = System.nanoTime();
            ClientIdentities.closeAll(Duration.ofMillis(200));
            long millis = (System.nanoTime() - started) / 1_000_000;
            assertTrue(millis >= 150 && millis < 5_000, "waited " + millis + " ms");
        } finally {
            ClientIdentities.handshakeEnded();
        }
    }

    @Test
    void withNoHandshakeRunningItDoesNotWaitAtAll() {
        long started = System.nanoTime();
        ClientIdentities.closeAll(Duration.ofSeconds(20));
        assertTrue((System.nanoTime() - started) / 1_000_000 < 1_000);
    }
}
