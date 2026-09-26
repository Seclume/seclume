package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Giving up every connection for a checkpoint, and filling again after the
 * restore - the pool side of seclume-crac.
 */
@Timeout(30)
class SuspendTest {

    @Test
    void suspendGivesUpEveryConnectionAndOpensNoneUntilResume() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = new PoolSettings();
        settings.setName("suspend");
        settings.setMaximumPoolSize(3);
        settings.setMinimumIdle(2);
        settings.setValidationTimeout(Duration.ofMillis(250));      // housekeeping every 250 ms
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            pool.warmup();
            Connection borrowed = pool.getConnection();
            assertEquals(2, source.openedCount());

            pool.suspend();
            assertEquals(1, pool.statistics().total(), "the idle one is closed at once");
            borrowed.close();
            assertEquals(0, pool.statistics().total(), "the borrowed one goes on its return");

            Thread.sleep(1000);                     // four housekeeping rounds
            assertEquals(0, pool.statistics().total(), "housekeeping refilled a suspended pool");
            assertEquals(2, source.openedCount());

            pool.resume();
            for (int i = 0; i < 40 && pool.statistics().total() < 2; i++) {
                Thread.sleep(100);
            }
            assertEquals(2, pool.statistics().total(), "the pool did not fill again");
            assertTrue(source.openedCount() >= 4, "not opened afresh");
        }
    }
}
