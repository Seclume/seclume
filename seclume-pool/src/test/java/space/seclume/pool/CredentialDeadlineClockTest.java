package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

/**
 * A credential's end is turned into a System.nanoTime deadline once, when the
 * connection is opened; from then on the wall clock plays no part. A clock
 * that jumps - NTP stepping, a restored checkpoint, the host's clock set by
 * hand - neither retires a connection whose 600 s lease is good nor keeps one
 * whose lease is over.
 */
class CredentialDeadlineClockTest {

    @Test
    void aWallClockJumpAfterTheOpenMovesNoDeadline() throws Exception {
        AtomicReference<Instant> validUntil = new AtomicReference<>(
                Instant.now().plusSeconds(600));
        PoolSettings settings = new PoolSettings();
        settings.setName("clock");
        settings.setMaximumPoolSize(1);
        settings.setConnectionTimeout(Duration.ofSeconds(5));
        settings.setCredentialExpiry(validUntil::get);
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            try (Connection c = pool.getConnection()) {
                assertTrue(c.isValid(1));
            }
            // As the supplier sees it, the clock jumped a year ahead: every
            // lease would be over. The connection opened before is not - its
            // deadline was fixed in nanoTime when it was opened.
            validUntil.set(Instant.now().minus(Duration.ofDays(365)));
            for (int i = 0; i < 3; i++) {
                try (Connection c = pool.getConnection()) {
                    assertTrue(c.isValid(1));
                }
            }
            assertEquals(1, source.openedCount(), "the connection was retired for a clock");
            assertFalse(source.handedOut().get(0).closed.get());
        }
    }
}
