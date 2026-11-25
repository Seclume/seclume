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
