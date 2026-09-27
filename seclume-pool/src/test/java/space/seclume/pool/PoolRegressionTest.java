package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The pool after the audit of 27.09.2026: permits given back on unchecked
 * failures, a credential expiry that cannot be read no longer taken for
 * "never", nothing leaked by a close racing a login, and a lapsed connection
 * never parked again.
 */
@Timeout(60)
class PoolRegressionTest {

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(3);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        settings.setValidationTimeout(Duration.ofMillis(200));
        return settings;
    }

    private static void waitUntil(java.util.function.BooleanSupplier condition, String what)
            throws InterruptedException {
        long end = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() - end > 0) {
                throw new AssertionError(what);
            }
            Thread.sleep(20);
        }
    }

    /**
     * A secret manager that is down makes every login fail unchecked. Each
     * housekeeping round used to keep one permit per missing idle connection,
     * so once it was back the pool could not open anything any more.
     */
    @Test
    void uncheckedLoginFailuresDuringReplenishKeepNoPermits() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setMinimumIdle(3);
        source.failUncheckedWith(new IllegalStateException("secret manager unreachable"));

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            Thread.sleep(1500);                       // several rounds of replenish
            source.succeedAgain();
            List<Connection> all = new ArrayList<>();
            try {
                for (int i = 0; i < settings.getMaximumPoolSize(); i++) {
                    all.add(pool.getConnection());
                }
            } finally {
                for (Connection connection : all) {
                    connection.close();
                }
            }
            assertEquals(settings.getMaximumPoolSize(), all.size(),
                    "the pool lost capacity to failed logins");
        }
    }

    @Test
    void anUncheckedFailureInWarmupKeepsNoPermit() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setMinimumIdle(1);
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            source.failUncheckedWith(new IllegalStateException("secret manager unreachable"));
            for (int i = 0; i < 10; i++) {
                assertThrows(IllegalStateException.class, pool::warmup);
            }
            source.succeedAgain();
            List<Connection> all = new ArrayList<>();
            try {
                for (int i = 0; i < settings.getMaximumPoolSize(); i++) {
                    all.add(pool.getConnection());
                }
            } finally {
                for (Connection connection : all) {
                    connection.close();
                }
            }
        }
    }

    // ---- N5 --------------------------------------------------------------

    @Test
    void anUnreadableExpiryWithoutMaxLifetimeGivesAShortLifeNotAnEndlessOne() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setMaxLifetime(Duration.ZERO);
        settings.setCredentialMargin(Duration.ofSeconds(30));
        settings.setCredentialExpiry(() -> {
            throw new IllegalStateException("Vault is not answering");
        });
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            long before = System.nanoTime();
            long deadline = pool.credentialDeadline();
            assertNotEquals(Long.MAX_VALUE, deadline, "treated as never expiring");
            long left = deadline - before;
            assertTrue(left > 0 && left <= Duration.ofSeconds(31).toNanos(), "left " + left);
        }
    }

    @Test
    void anUnreadableExpiryWithAMaxLifetimeIsBoundedByIt() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setMaxLifetime(Duration.ofMinutes(30));
        settings.setCredentialExpiry(() -> {
            throw new IllegalStateException("Vault is not answering");
        });
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            // No deadline of its own: maxLifetime retires it, and a blip of the
            // secret manager does not empty the pool.
            assertEquals(Long.MAX_VALUE, pool.credentialDeadline());
        }
    }

    @Test
    void anExpiryCenturiesAwayDoesNotOverflow() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setCredentialExpiry(() -> Instant.MAX);
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            assertEquals(Long.MAX_VALUE, pool.credentialDeadline());
            pool.getConnection().close();              // and a login is not broken by it
            assertEquals(1, pool.idleCount());
        }
    }

    @Test
    void anExpiryCenturiesAgoHasLapsed() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setCredentialExpiry(() -> Instant.MIN);
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            long deadline = pool.credentialDeadline();
            assertTrue(System.nanoTime() - deadline >= 0, "an expiry in the past has not lapsed");
        }
    }

    // ---- P1: a connection whose credential has expired never goes back ---

    @Test
    void aConnectionWhoseCredentialExpiredWhileBorrowedIsNotParked() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setMaxLifetime(Duration.ZERO);
        settings.setCredentialMargin(Duration.ZERO);
        settings.setCredentialSpread(Duration.ZERO);
        Instant expiry = Instant.now().plusMillis(300);
        settings.setCredentialExpiry(() -> expiry);
        // Housekeeping far apart, so that only the return itself can catch it.
        settings.setValidationTimeout(Duration.ofSeconds(30));

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            Connection connection = pool.getConnection();
            Thread.sleep(500);                         // expires while borrowed
            connection.close();
            assertEquals(0, pool.idleCount(), "an expired connection was parked again");
            assertTrue(source.handedOut().get(0).closed.get(), "and it was not closed");
        }
    }

    @Test
    void aConnectionMerelyInsideItsMarginIsParkedForThePlannedReplacement() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setMaxLifetime(Duration.ZERO);
        settings.setCredentialMargin(Duration.ofMinutes(1));
        settings.setCredentialSpread(Duration.ZERO);
        settings.setCredentialExpiry(() -> Instant.now().plusSeconds(30));
        settings.setValidationTimeout(Duration.ofSeconds(30));

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            pool.getConnection().close();
            assertEquals(1, pool.idleCount(),
                    "retired at once although its credential is still valid for 30 s");
        }
    }

    @Test
    void theEndIsTheCredentialsAndTheDeadlineAMarginBefore() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setCredentialMargin(Duration.ofMinutes(1));
        settings.setCredentialSpread(Duration.ZERO);
        settings.setCredentialExpiry(() -> Instant.now().plusSeconds(3600));
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            SeclumePool.CredentialTimes times = pool.credentialTimes();
            long gap = times.expires() - times.deadline();
            assertTrue(Math.abs(gap - Duration.ofMinutes(1).toNanos())
                    < Duration.ofSeconds(1).toNanos(), "gap " + Duration.ofNanos(gap));
        }
    }

    // ---- N7 and the close race -------------------------------------------

    @Test
    void aLoginThatFinishesAfterCloseIsClosedNotLeaked() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        SeclumePool pool = new SeclumePool(source, settings);
        source.beforeReturn(() -> pool.close(Duration.ZERO));   // close lands mid-login

        assertThrows(SQLException.class, pool::getConnection);

        assertEquals(1, source.handedOut().size());
        assertTrue(source.handedOut().get(0).closed.get(),
                "the session opened while the pool closed was left open");
    }

    @Test
    void aDeadlineThatFailsAfterTheLoginClosesTheConnection() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        AtomicReference<Error> fail = new AtomicReference<>();
        settings.setCredentialExpiry(() -> {
            Error error = fail.get();
            if (error != null) {
                throw error;
            }
            return Instant.now().plusSeconds(3600);
        });
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            fail.set(new AssertionError("expiry blew up"));
            assertThrows(AssertionError.class, pool::getConnection);
            assertEquals(1, source.handedOut().size());
            assertTrue(source.handedOut().get(0).closed.get(),
                    "the connection opened before the failure was left open");
        }
    }
}
