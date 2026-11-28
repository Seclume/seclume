package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The rotation counter decides which connections were opened with the old
 * secret. Eight threads rotating at once must count every rotation: a lost
 * one would leave a connection of the old secret looking current.
 */
@Timeout(120)
class RotationCounterTest {

    @Test
    void everyRotationIsCountedUnderContention() throws Exception {
        PoolSettings settings = new PoolSettings();
        settings.setName("rotations");
        settings.setMaximumPoolSize(2);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofMillis(500));
        settings.setShutdownTimeout(Duration.ZERO);
        int threads = 8;
        int each = 10_000;
        try (SeclumePool pool = new SeclumePool(new StubDataSource(), settings)) {
            long before = pool.rotations();
            CountDownLatch start = new CountDownLatch(1);
            List<Thread> rotating = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                Thread thread = new Thread(() -> {
                    try {
                        start.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                    for (int i = 0; i < each; i++) {
                        pool.rotateSecret(false);
                    }
                });
                thread.start();
                rotating.add(thread);
            }
            start.countDown();
            for (Thread thread : rotating) {
                thread.join();
            }
            assertEquals(before + (long) threads * each, pool.rotations());
        }
    }
}
