package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.stream.LongStream;

import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.SessionReset;

/**
 * {@link PoolStateMachineTest} with the threads an application has: several
 * borrowers at once, a thread answering and refusing resets late, suspending
 * and resuming - and the pool closed while all of it is under way. What a
 * single thread cannot reach is exactly where the review of the reset path
 * found its defect: {@code close()} against a borrower reading a reset
 * answer.
 *
 * <p>The promises, checked as they happen on every thread:
 * <ul>
 *   <li>no connection is lent while the reset of its last use is unconfirmed;</li>
 *   <li>a connection whose reset was refused is never lent again;</li>
 *   <li>no connection is lent to two holders at once;</li>
 *   <li>no session is closed while a reset answer is being read from it;</li>
 *   <li>once the pool is closed and every borrower is gone, every connection is closed.</li>
 * </ul>
 *
 * <p>Thread scheduling is not reproducible, so a seed fixes the choices, not
 * the interleaving; a failure names the seed and what was violated.
 * {@code -Dseclume.pool.concurrent.seeds=N} runs more.
 */
@Timeout(300)
class ConcurrentPoolStateMachineTest {

    private static final int BORROWERS = 4;
    private static final int STEPS = 300;

    static LongStream seeds() {
        return LongStream.range(0, Long.getLong("seclume.pool.concurrent.seeds", 25));
    }

    /** A reset whose answer arrives when another thread says so. */
    private static final class SlowReset implements SessionReset {
        final StubDataSource.StubConnection physical;
        final Queue<String> violations;
        volatile boolean owed;
        volatile boolean answered;
        volatile boolean refuseNext;
        volatile boolean refused;
        volatile boolean reading;

        SlowReset(StubDataSource.StubConnection physical, Queue<String> violations) {
            this.physical = physical;
            this.violations = violations;
        }

        @Override
        public boolean sessionStateChanged() {
            return false;
        }

        @Override
        public boolean resetSessionState() {
            owed = true;
            answered = false;
            return true;
        }

        @Override
        public boolean resetOwed() {
            return owed;
        }

        @Override
        public boolean resetAnswered() {
            return !owed || answered;
        }

        @Override
        public void settleReset() throws SQLException {
            if (!owed) {
                return;
            }
            reading = true;
            try {
                // The answer is on its way: wait for it, as a driver does,
                // but not for ever - the answering thread may already be done.
                long until = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(20);
                while (!answered && System.nanoTime() < until) {
                    LockSupport.parkNanos(200_000);
                }
                if (physical.closed.get()) {
                    violations.add("a session was closed while its reset answer was read");
                }
                owed = false;
                if (refuseNext) {
                    refused = true;
                    throw new SQLException("the reset was refused", "08006");
                }
            } finally {
                reading = false;
            }
        }
    }

    @ParameterizedTest(name = "seed {0}")
    @MethodSource("seeds")
    void thePromisesHoldUnderConcurrency(long seed) throws Exception {
        Random setup = new Random(seed);
        int size = 1 + setup.nextInt(3);
        Queue<String> violations = new ConcurrentLinkedQueue<>();
        StubDataSource source = new StubDataSource();
        Map<StubDataSource.StubConnection, SlowReset> resets = new ConcurrentHashMap<>();
        source.beforeReturn(() -> {
            List<StubDataSource.StubConnection> all = source.handedOut();
            StubDataSource.StubConnection newest = all.get(all.size() - 1);
            SlowReset reset = new SlowReset(newest, violations);
            newest.sessionReset = reset;
            resets.put(newest, reset);
        });

        PoolSettings settings = new PoolSettings();
        settings.setName("concurrent-state-machine");
        settings.setMaximumPoolSize(size);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofMillis(30));
        settings.setShutdownTimeout(Duration.ofMillis(setup.nextInt(50)));
        SeclumePool pool = new SeclumePool(source, settings);

        Map<StubDataSource.StubConnection, Thread> holders = new ConcurrentHashMap<>();
        CountDownLatch done = new CountDownLatch(BORROWERS);
        List<Thread> threads = new ArrayList<>();
        for (int t = 0; t < BORROWERS; t++) {
            long threadSeed = seed * 31 + t;
            threads.add(Thread.ofPlatform().start(() -> {
                try {
                    borrowAndReturn(pool, source, resets, holders, violations,
                            new Random(threadSeed));
                } catch (Throwable unexpected) {
                    violations.add("a borrower failed: " + unexpected);
                } finally {
                    done.countDown();
                }
            }));
        }
        Random chaos = new Random(seed ^ 0x5EC1);
        Thread meddler = Thread.ofPlatform().start(() -> {
            while (done.getCount() > 0) {
                List<SlowReset> all = new ArrayList<>(resets.values());
                if (!all.isEmpty()) {
                    SlowReset one = all.get(chaos.nextInt(all.size()));
                    switch (chaos.nextInt(10)) {
                        case 0 -> one.refuseNext = true;
                        case 1 -> pool.suspend();
                        case 2 -> pool.resume();
                        default -> one.answered = true;
                    }
                }
                LockSupport.parkNanos(100_000 + chaos.nextInt(400_000));
            }
        });
        // Closed at a random moment while the borrowers are still at work.
        Thread.sleep(5 + chaos.nextInt(40));
        pool.close();

        assertTrue(done.await(60, TimeUnit.SECONDS), "seed " + seed + ": borrowers hang");
        for (Thread thread : threads) {
            thread.join();
        }
        meddler.join();
        for (StubDataSource.StubConnection physical : source.handedOut()) {
            if (!physical.closed.get()) {
                violations.add("a connection outlived the closed pool");
            }
        }
        assertTrue(violations.isEmpty(), "seed " + seed + ", pool of " + size + ": "
                + violations.stream().distinct().toList());
    }

    private static void borrowAndReturn(SeclumePool pool, StubDataSource source,
                                        Map<StubDataSource.StubConnection, SlowReset> resets,
                                        Map<StubDataSource.StubConnection, Thread> holders,
                                        Queue<String> violations, Random random) {
        for (int step = 0; step < STEPS; step++) {
            Connection handle;
            try {
                handle = pool.getConnection();
            } catch (SQLException timedOutOrClosed) {
                if (pool.isClosed()) {
                    return;
                }
                continue;
            }
            StubDataSource.StubConnection physical = physicalOf(source, handle);
            SlowReset reset = resets.get(physical);
            if (reset.owed) {
                violations.add("lent while the reset of its last use was unconfirmed");
            }
            if (reset.refused) {
                violations.add("lent again after its reset was refused");
            }
            if (holders.putIfAbsent(physical, Thread.currentThread()) != null) {
                violations.add("lent to two holders at once");
            }
            try {
                if (random.nextInt(4) > 0) {
                    try (Statement statement = handle.createStatement()) {
                        statement.isClosed();
                    } catch (SQLException brokenOrClosed) {
                        // a broken connection, or the pool cut it on close
                    }
                }
                if (random.nextInt(25) == 0) {
                    physical.broken = true;
                }
                if (random.nextInt(3) == 0) {
                    LockSupport.parkNanos(random.nextInt(300_000));
                }
            } finally {
                holders.remove(physical, Thread.currentThread());
                try {
                    handle.close();
                } catch (SQLException ignored) {
                    // closing a handle the pool already cut
                }
            }
        }
    }

    private static StubDataSource.StubConnection physicalOf(StubDataSource source,
                                                           Connection handle) {
        Connection delegate = ((PooledConnection) handle).delegate();
        for (StubDataSource.StubConnection candidate : source.handedOut()) {
            if (candidate.proxy == delegate) {
                return candidate;
            }
        }
        throw new AssertionError("a connection the source never opened was lent");
    }
}
