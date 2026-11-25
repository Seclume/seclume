package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * rotateSecret retired connections on their return only: one held for good -
 * a batch, a leak - kept the old login until maxLifetime, which is what a
 * rotation after a leaked password is meant to end. With a grace, it is
 * closed under its borrower once the grace is over; one borrowed after the
 * rotation is not touched.
 */
@Timeout(30)
class RotationGraceTest {

    @Test
    void aConnectionHeldOverTheGraceIsClosed() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(2);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            Connection held = pool.getConnection();
            pool.rotateSecret(true, Duration.ofMillis(200));
            Connection fresh = pool.getConnection();
            long until = System.nanoTime() + Duration.ofSeconds(10).toNanos();
            while (!held.isClosed() && System.nanoTime() < until) {
                Thread.sleep(20);
            }
            assertTrue(held.isClosed(), "the old login was kept past the grace");
            assertTrue(source.handedOut().get(0).closed.get(), "the driver's connection is open");
            assertFalse(fresh.isClosed(), "a connection of the new login was closed");
            fresh.close();
            held.close();                                // a no-op now, and no harm
        }
    }
}
