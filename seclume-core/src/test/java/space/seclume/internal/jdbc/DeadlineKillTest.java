package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

/**
 * The stage after the cancellation: a server that ignores it and trickles a
 * byte now and then defeats a network timeout, which counts only silence. The
 * deadline closes the connection after its grace - and never once the
 * statement is over, when the connection may already be someone else's. All
 * four drivers hand their statements' deadlines the same kill: closing the
 * session's transport.
 */
@ResourceLock("seclume.queryTimeoutGraceSeconds")
class DeadlineKillTest {

    @Test
    void aCancellationTheServerIgnoresEndsInTheConnectionClosed() throws Exception {
        String before = System.getProperty("seclume.queryTimeoutGraceSeconds");
        System.setProperty("seclume.queryTimeoutGraceSeconds", "1");
        try {
            AtomicInteger cancelled = new AtomicInteger();
            CountDownLatch killed = new CountDownLatch(1);
            long started = System.nanoTime();
            try (Deadline deadline = Deadline.of(1, cancelled::incrementAndGet, killed::countDown)) {
                // The statement does not end: the server ignored the cancel.
                assertTrue(killed.await(10, TimeUnit.SECONDS), "the connection was never closed");
                assertTrue(deadline.expired());
            }
            long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            assertEquals(1, cancelled.get(), "the cancellation comes first");
            assertTrue(took >= 1900, "closed before the grace was over: " + took + " ms");
        } finally {
            if (before == null) {
                System.clearProperty("seclume.queryTimeoutGraceSeconds");
            } else {
                System.setProperty("seclume.queryTimeoutGraceSeconds", before);
            }
        }
    }

    /**
     * A cancellation that blocks - MySQL's is a login and a KILL, and a busy
     * server let that login take the connect timeout - ran on the one
     * scheduler thread: its own kill and every other deadline of the process
     * waited behind it. Neither waits now.
     */
    @Test
    void aBlockingCancellationHoldsUpNeitherItsKillNorAnotherDeadline() throws Exception {
        String before = System.getProperty("seclume.queryTimeoutGraceSeconds");
        System.setProperty("seclume.queryTimeoutGraceSeconds", "1");
        CountDownLatch releaseTheBlocker = new CountDownLatch(1);
        try {
            CountDownLatch killed = new CountDownLatch(1);
            CountDownLatch otherCancelled = new CountDownLatch(1);
            long started = System.nanoTime();
            try (Deadline blocked = Deadline.of(1, () -> releaseTheBlocker.await(20, TimeUnit.SECONDS),
                    killed::countDown);
                 Deadline other = Deadline.of(1, otherCancelled::countDown)) {
                assertTrue(otherCancelled.await(4, TimeUnit.SECONDS),
                        "another statement's deadline waited behind a blocking cancellation");
                assertTrue(killed.await(5, TimeUnit.SECONDS),
                        "the kill waited behind its own blocking cancellation");
                assertTrue(blocked.expired() && other.expired());
            }
            long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            assertTrue(took < 5_000, "took " + took + " ms");
        } finally {
            releaseTheBlocker.countDown();
            if (before == null) {
                System.clearProperty("seclume.queryTimeoutGraceSeconds");
            } else {
                System.setProperty("seclume.queryTimeoutGraceSeconds", before);
            }
        }
    }

    /**
     * close() at the very moment the kill is due, two hundred times at once:
     * a kill either comes and ends before close() has returned - close()
     * waits for one under way - or not at all. One after it would close a connection that may
     * already be the next borrower's.
     */
    @Test
    void noKillComesAfterCloseHasReturned() throws Exception {
        String before = System.getProperty("seclume.queryTimeoutGraceSeconds");
        System.setProperty("seclume.queryTimeoutGraceSeconds", "0");
        try {
            AtomicInteger late = new AtomicInteger();
            AtomicInteger kills = new AtomicInteger();
            java.util.List<Thread> runs = new java.util.ArrayList<>();
            java.util.Random jitter = new java.util.Random(253);
            for (int run = 0; run < 200; run++) {
                long closeAfter = 1_000 + jitter.nextInt(41) - 20;   // 980 to 1020 ms
                runs.add(Thread.ofVirtual().start(() -> {
                    java.util.concurrent.atomic.AtomicBoolean returned =
                            new java.util.concurrent.atomic.AtomicBoolean();
                    Deadline deadline = Deadline.of(1, () -> { }, () -> {
                        // A close takes a moment; one that close() did not wait
                        // for is still going when close() has returned.
                        kills.incrementAndGet();
                        if (returned.get()) {
                            late.incrementAndGet();
                        }
                        Thread.sleep(30);
                        if (returned.get()) {
                            late.incrementAndGet();
                        }
                    });
                    try {
                        Thread.sleep(closeAfter);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    deadline.close();
                    returned.set(true);
                }));
            }
            for (Thread run : runs) {
                run.join(30_000);
            }
            Thread.sleep(300);                                      // a straggler would land now
            assertEquals(0, late.get(), "kills after close() had returned, of " + kills.get());
        } finally {
            if (before == null) {
                System.clearProperty("seclume.queryTimeoutGraceSeconds");
            } else {
                System.setProperty("seclume.queryTimeoutGraceSeconds", before);
            }
        }
    }

    @Test
    void aStatementThatEndedInTimeIsNeitherCancelledNorClosed() throws Exception {
        AtomicInteger cancelled = new AtomicInteger();
        AtomicInteger killed = new AtomicInteger();
        try (Deadline deadline = Deadline.of(1, cancelled::incrementAndGet,
                killed::incrementAndGet)) {
            assertTrue(!deadline.expired());
        }
        Thread.sleep(3500);
        assertEquals(0, cancelled.get());
        assertEquals(0, killed.get(), "a connection was closed after its statement was over");
    }
}
