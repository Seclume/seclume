package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * A waiting borrower is woken by what it waits for - a connection given back,
 * a permit freed - and each such event wakes a waiter of its own.
 *
 * <p>The safety-net park is lengthened to a minute here, so that a waiter
 * that is not woken shows as one that waits: before, a return woke the head
 * of the queue, and two returns in a row woke the same thread twice; the
 * second connection then lay idle until the second waiter's 2 ms park ran
 * out. That park, flat at 2 ms for every waiter, was what made 496 waiters
 * wake 248,000 times a second for nothing.
 *
 * <p>Isolated: the safety net is the pool's, for every pool in the JVM.
 */
@Isolated
@Timeout(60)
class WaiterWakeupTest {

    private long first;
    private long most;

    @BeforeEach
    void lengthenTheSafetyNet() {
        first = SeclumePool.PARK_NANOS;
        most = SeclumePool.PARK_MAX_NANOS;
        SeclumePool.PARK_NANOS = TimeUnit.MINUTES.toNanos(1);
        SeclumePool.PARK_MAX_NANOS = TimeUnit.MINUTES.toNanos(1);
    }

    @AfterEach
    void restoreIt() {
        SeclumePool.PARK_NANOS = first;
        SeclumePool.PARK_MAX_NANOS = most;
    }

    private static PoolSettings settings(int size) {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(size);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(50));
        return settings;
    }

    private final CountDownLatch letGo = new CountDownLatch(1);

    /**
     * Starts {@code n} threads that borrow, count, and keep the connection
     * until the test lets go: a waiter served must not, by giving its
     * connection back, wake the next one - that would hide a wakeup lost.
     */
    private List<Thread> waiters(SeclumePool pool, int n, AtomicInteger served, CountDownLatch done) {
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            threads.add(Thread.ofVirtual().start(() -> {
                try (Connection c = pool.getConnection()) {
                    served.incrementAndGet();
                    done.countDown();
                    letGo.await();
                    c.getAutoCommit();
                } catch (SQLException | InterruptedException e) {
                    throw new AssertionError(e);
                }
            }));
        }
        return threads;
    }

    private void finish(List<Thread> threads) throws InterruptedException {
        letGo.countDown();
        for (Thread t : threads) {
            t.join();
        }
    }

    private static void untilWaiting(SeclumePool pool, int n) throws InterruptedException {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (pool.waitingCount() < n) {
            assertTrue(System.nanoTime() < until, "the waiters never started waiting");
            Thread.sleep(1);
        }
    }

    @Test
    void twoReturnsInARowWakeTwoWaiters() throws Exception {
        try (SeclumePool pool = new SeclumePool(new StubDataSource(), settings(2))) {
            Connection one = pool.getConnection();
            Connection two = pool.getConnection();
            AtomicInteger served = new AtomicInteger();
            CountDownLatch done = new CountDownLatch(2);
            List<Thread> threads = waiters(pool, 2, served, done);
            untilWaiting(pool, 2);

            one.close();
            two.close();

            assertTrue(done.await(10, TimeUnit.SECONDS),
                    "a returned connection lay idle while a waiter slept: " + served.get() + " of 2 served");
            finish(threads);
        }
    }

    @Test
    void everyReturnOfABurstReachesAWaiter() throws Exception {
        try (SeclumePool pool = new SeclumePool(new StubDataSource(), settings(8))) {
            List<Connection> held = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                held.add(pool.getConnection());
            }
            AtomicInteger served = new AtomicInteger();
            CountDownLatch done = new CountDownLatch(8);
            List<Thread> threads = waiters(pool, 64, served, done);
            untilWaiting(pool, 64);

            for (Connection c : held) {
                c.close();
            }

            assertTrue(done.await(10, TimeUnit.SECONDS),
                    "waiters slept through returns: " + served.get() + " of 8 served");
            assertEquals(56, pool.waitingCount(), "the rest still wait");
            finish(threads);
            assertEquals(64, served.get());
            assertEquals(0, pool.waitingCount());
        }
    }

    @Test
    void aFreedPermitWakesAWaiterThatOpensANewConnection() throws Exception {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings(1))) {
            Connection only = pool.getConnection();
            AtomicInteger served = new AtomicInteger();
            CountDownLatch done = new CountDownLatch(1);
            List<Thread> threads = waiters(pool, 1, served, done);
            untilWaiting(pool, 1);

            pool.detach(only).close();

            assertTrue(done.await(10, TimeUnit.SECONDS), "the freed permit woke nobody");
            assertEquals(2, source.openedCount(), "the waiter opened a connection of its own");
            finish(threads);
        }
    }
}
