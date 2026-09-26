package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Connections are replaced before their credential lapses, not after.
 *
 * <p>This is the half of dynamic credentials that usually goes missing.
 * Fetching a password out of Vault is the easy part and every client does it;
 * what nobody does is notice that the password a connection was opened with
 * <b>expires while that connection is sitting idle in a pool</b>. The failure
 * mode is an authentication error in a running application at an hour nobody
 * chose, and the usual workaround is to set {@code maxLifetime} shorter than
 * the TTL by hand, in a second place, and to remember it when the TTL changes.
 *
 * <p>So the pool asks - through {@code PoolSettings.credentialExpiry}, which
 * is how it learns this without knowing anything about secret providers - and
 * retires early. These tests pin down both directions: that it does retire,
 * and that a source which says nothing changes nothing.
 */
@Timeout(60)
class CredentialExpiryTest {

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(4);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(5));
        // Housekeeping runs at the beat of the validation timeout.
        settings.setValidationTimeout(Duration.ofMillis(200));
        settings.setMaxLifetime(Duration.ZERO);      // so only the credential can retire it
        settings.setIdleTimeout(Duration.ZERO);
        return settings;
    }

    private static void waitUntil(java.util.function.BooleanSupplier condition, String what)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (!condition.getAsBoolean() && System.currentTimeMillis() < deadline) {
            Thread.sleep(25);
        }
        assertTrue(condition.getAsBoolean(), what);
    }

    /**
     * A credential that has already lapsed: the idle connection goes.
     *
     * <p>The expiry is in the past from the start, so there is no waiting for
     * a clock - the point being tested is that housekeeping looks at the
     * credential at all, not how long it takes to notice.
     */
    @Test
    void anIdleConnectionWithALapsedCredentialIsRetired() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setCredentialExpiry(() -> Instant.now().minusSeconds(1));
        settings.setCredentialMargin(Duration.ZERO);

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            try (Connection connection = pool.getConnection()) {
                assertTrue(!connection.isClosed());
            }
            // It is back in the pool now - and must not stay there.
            waitUntil(() -> pool.idleCount() == 0, "the lapsed connection stayed in the pool");
        }
    }

    /**
     * The margin is what makes it useful.
     *
     * <p>Retiring at the moment of expiry is too late: a connection handed out
     * a millisecond earlier is still in use when the credential dies. The
     * margin moves the decision forward, and here the credential is still
     * valid for half a minute while the margin is a full one - so it has to go
     * already.
     */
    @Test
    void theMarginRetiresBeforeTheCredentialActuallyExpires() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setCredentialExpiry(() -> Instant.now().plusSeconds(30));
        settings.setCredentialMargin(Duration.ofMinutes(1));

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            pool.getConnection().close();
            waitUntil(() -> pool.idleCount() == 0,
                    "a connection inside the margin was kept");
        }
    }

    /** Comfortably valid: nothing is retired, and the pool behaves as ever. */
    @Test
    void aCredentialWithPlentyOfTimeChangesNothing() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setCredentialExpiry(() -> Instant.now().plusSeconds(3600));
        settings.setCredentialMargin(Duration.ofMinutes(1));

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            pool.getConnection().close();
            assertEquals(1, pool.idleCount());
            Thread.sleep(600);                       // several housekeeping rounds
            assertEquals(1, pool.idleCount(), "a perfectly good connection was retired");
        }
    }

    /**
     * The default: no expiry configured, nothing changes.
     *
     * <p>The control for all of the above. Without it the three tests could
     * pass against a pool that simply closed idle connections.
     */
    @Test
    void aStaticPasswordIsUnaffected() throws Exception {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            pool.getConnection().close();
            assertEquals(1, pool.idleCount());
            Thread.sleep(600);
            assertEquals(1, pool.idleCount(), "a pool without an expiry retired a connection");
        }
    }

    /**
     * A source that answers {@code null} means "does not expire".
     *
     * <p>That is what a password in a file answers, and reading it as "expired
     * now" would turn every static deployment into a connection churn.
     */
    @Test
    void nullMeansItDoesNotExpire() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setCredentialExpiry(() -> null);

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            pool.getConnection().close();
            Thread.sleep(600);
            assertEquals(1, pool.idleCount());
        }
    }

    /**
     * A source that throws is treated as one that does not expire.
     *
     * <p>A secret manager being briefly unreachable must not empty the pool -
     * that would turn a blip into an outage, and the connections already open
     * are still working.
     */
    @Test
    void aFailingExpiryQueryDoesNotEmptyThePool() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setCredentialExpiry(() -> {
            throw new IllegalStateException("Vault is not answering");
        });

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            pool.getConnection().close();
            Thread.sleep(600);
            assertEquals(1, pool.idleCount(), "an unreachable secret manager emptied the pool");
        }
    }

    /**
     * Each connection carries the credential it was opened with.
     *
     * <p>Worth pinning down because the tempting alternative is wrong. When a
     * credential is rotated, the connection already open was authenticated
     * with the <b>old</b> one and the server is still happy with it until that
     * one runs out - throwing it away immediately would mean a pool that
     * empties itself on every rotation for no gain.
     *
     * <p>So: the existing connection stays on its own deadline, and a
     * connection opened after the rotation gets the new one. Two entries in
     * one pool, retired at different times, which is exactly what a rolling
     * credential should look like.
     */
    @Test
    void eachConnectionKeepsTheDeadlineItWasOpenedWith() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        AtomicReference<Instant> expiry = new AtomicReference<>(Instant.now().plusSeconds(3600));
        settings.setCredentialExpiry(expiry::get);
        settings.setCredentialMargin(Duration.ofMinutes(1));

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            Connection first = pool.getConnection();

            // Rotated to a credential that is already inside the margin. The
            // second connection is opened under it - the first is not.
            expiry.set(Instant.now().plusSeconds(10));
            Connection second = pool.getConnection();

            first.close();
            second.close();

            waitUntil(() -> pool.idleCount() == 1,
                    "expected the newly opened connection to go and the older one to stay");
            Thread.sleep(600);
            assertEquals(1, pool.idleCount(),
                    "the connection opened under the still-valid credential was retired too");
        }
    }

    /**
     * The replacement exists before the old connection is taken away.
     *
     * <p>Without this the pool retires and then refills, in that order, and
     * for the moment in between a cohort that lapsed together leaves nothing
     * behind. What that costs is not an outage - it is every caller arriving
     * in that moment paying a full handshake, and with a dynamic credential an
     * HTTP round trip to fetch the password first. It shows up as an
     * unexplained latency spike on the hour and is very hard to attribute.
     */
    @Test
    void aReplacementIsOpenedBeforeTheLapsedOneIsRetired() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setMinimumIdle(0);
        settings.setMaximumPoolSize(4);
        settings.setCredentialExpiry(() -> Instant.now().minusSeconds(1));
        settings.setCredentialMargin(Duration.ZERO);
        settings.setCredentialSpread(Duration.ZERO);

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            try (Connection connection = pool.getConnection()) {
                assertTrue(!connection.isClosed());
            }
            waitUntil(() -> pool.statistics().prewarmed() > 0,
                    "no replacement was opened ahead of the retirement");
            assertTrue(pool.statistics().retired() > 0,
                    "the lapsed connection was never retired");
        }
    }

    /**
     * At the maximum there is nowhere to put a replacement, and it says so by
     * not pretending.
     *
     * <p>Taking a permit that is not free would be growing the pool past the
     * size an operator set, which is worse than the gap it would close.
     */
    @Test
    void atTheMaximumItDegradesToRetireThenRefill() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setMinimumIdle(1);
        settings.setMaximumPoolSize(1);
        settings.setCredentialExpiry(() -> Instant.now().minusSeconds(1));
        settings.setCredentialMargin(Duration.ZERO);
        settings.setCredentialSpread(Duration.ZERO);

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            try (Connection connection = pool.getConnection()) {
                assertTrue(!connection.isClosed());
            }
            waitUntil(() -> pool.statistics().retired() > 0, "nothing was retired");
            assertEquals(0, pool.statistics().prewarmed(),
                    "a pool at its maximum grew past it to prewarm");
        }
    }

    /**
     * A cohort opened together does not reach its deadline together.
     *
     * <p>Ten connections made in the same burst by the same credential share
     * an expiry to the second. Retiring them in one housekeeping round is the
     * thing the spread exists to prevent, so what is asserted is that the rule
     * produces different answers - the mechanism, not a distribution, and not
     * how long it takes to observe one.
     */
    @Test
    void theDeadlinesOfACohortAreSpreadOut() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setMinimumIdle(0);
        settings.setCredentialExpiry(() -> Instant.now().plusSeconds(3600));
        settings.setCredentialMargin(Duration.ofMinutes(1));
        settings.setCredentialSpread(Duration.ofMinutes(10));

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            java.util.Set<Long> deadlines = new java.util.HashSet<>();
            for (int i = 0; i < 20; i++) {
                deadlines.add(pool.credentialDeadline());
            }
            assertTrue(deadlines.size() > 1,
                    "every connection of a cohort would get the same deadline, so they "
                    + "would all be retired in one round - which is what the spread is for");
        }
    }

    /** And with the spread switched off, the old behaviour is back. */
    @Test
    void withoutASpreadTheDeadlineIsJustTheMargin() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setMinimumIdle(0);
        settings.setCredentialExpiry(() -> Instant.now().plusSeconds(3600));
        settings.setCredentialMargin(Duration.ofMinutes(1));
        settings.setCredentialSpread(Duration.ZERO);

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            long first = pool.credentialDeadline();
            long second = pool.credentialDeadline();
            // Not equal - the clock moves between the two calls - but within a
            // moment of each other rather than minutes apart.
            assertTrue(Math.abs(second - first) < Duration.ofSeconds(1).toNanos(),
                    "the deadlines are " + Duration.ofNanos(Math.abs(second - first))
                    + " apart with the spread switched off");
        }
    }

    /**
     * A busy pool has no idle moment, and the sweep was the only way out.
     *
     * <p>Every retirement used to happen in the idle sweep, which can only
     * touch a connection it finds sitting in the pool. A pool under load has
     * none sitting: a returned connection is claimed again long before
     * housekeeping's next round comes. So the case where a lapsed credential
     * matters most - a busy application - was the one where nothing retired
     * it, and the same connection went out again and again.
     *
     * <p>Found by the rotation benchmark: six threads on six connections
     * across an expiry, four retirements out of six, then nothing for thirty
     * seconds.
     *
     * <p><b>How it is made deterministic.</b> The connection is held across a
     * housekeeping round, so it is borrowed at the moment the pool sees that
     * its credential has gone - the situation the sweep cannot act on. Then
     * it is returned and another is borrowed immediately: a gap of
     * microseconds, in which no sweep could have retired it. Whether the next
     * borrow gets the same connection is therefore the mark's doing and
     * nothing else's.
     */
    @Test
    void aLapsedConnectionIsNotHandedOutAgainWhenTheSweepNeverGetsAChance() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setMaximumPoolSize(2);
        settings.setMinimumIdle(0);
        settings.setCredentialExpiry(() -> Instant.now().minusSeconds(1));
        settings.setCredentialMargin(Duration.ZERO);
        settings.setCredentialSpread(Duration.ZERO);

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            Connection held = pool.getConnection();
            StubDataSource.StubConnection mine = source.handedOut().get(0);

            // Long enough for housekeeping to have looked at it while it was
            // out. It cannot retire it there - somebody is using it.
            Thread.sleep(600);
            assertFalse(mine.closed.get(), "a borrowed connection was closed under its holder");
            assertFalse(held.isClosed(), "the handle was closed under its holder");

            held.close();
            try (Connection next = pool.getConnection()) {
                assertTrue(!next.isClosed());
            }
            assertTrue(mine.closed.get(),
                    "the connection with the lapsed credential went back into the pool and "
                            + "came straight out again: " + pool.statistics());
        }
    }
}
