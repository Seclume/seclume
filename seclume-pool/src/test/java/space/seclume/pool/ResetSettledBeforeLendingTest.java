package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.SessionReset;

/**
 * A reset whose answer is still on its way is settled before the connection
 * is lent again - by the next borrower that takes it, which takes another
 * one first while the answer has not arrived - and a refused one retires the
 * connection.
 */
@Timeout(30)
class ResetSettledBeforeLendingTest {

    /** A reset that is sent at once and answered when the test says so. */
    private static final class Deferred implements SessionReset {
        final CountDownLatch answer = new CountDownLatch(1);
        volatile boolean owed;
        volatile boolean settled;
        volatile boolean refuse;

        @Override
        public boolean sessionStateChanged() {
            return false;
        }

        @Override
        public boolean resetSessionState() {
            owed = true;
            settled = false;
            return true;
        }

        @Override
        public boolean resetOwed() {
            return owed;
        }

        @Override
        public boolean resetAnswered() {
            return !owed || answer.getCount() == 0;
        }

        @Override
        public void settleReset() throws SQLException {
            try {
                answer.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            owed = false;
            if (refuse) {
                throw new SQLException("the reset was refused");
            }
            settled = true;
        }
    }

    private static PoolSettings settings(int size) {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(size);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(5));
        settings.setShutdownTimeout(Duration.ZERO);
        return settings;
    }

    /**
     * A connection whose reset answer has not arrived is passed over for one
     * that is ready: reading it would wait a round trip. It is the one this
     * thread gave back last, so without that the overlap would be lost.
     */
    @Test
    void aConnectionWithItsResetOnTheWayIsPassedOverForAReadyOne() throws Exception {
        StubDataSource source = new StubDataSource();
        Deferred reset = new Deferred();
        try (SeclumePool pool = new SeclumePool(source, settings(2))) {
            Connection first = pool.getConnection();
            Connection other = pool.getConnection();
            StubDataSource.StubConnection physical = source.handedOut().getFirst();
            StubDataSource.StubConnection ready = source.handedOut().get(1);
            physical.sessionReset = reset;
            other.close();                                   // nothing used, nothing owed
            try (Statement statement = first.createStatement()) {
                assertFalse(statement.isClosed());
            }
            first.close();                                   // returns at once
            assertTrue(reset.owed, "the reset was sent and is owed");

            try (Connection second = pool.getConnection()) {
                assertSame(ready.proxy, ((PooledConnection) second).delegate(),
                        "the connection whose reset is unanswered was taken first");
            }

            reset.answer.countDown();
            // Both at once: the one whose reset was owed is settled and lent.
            try (Connection a = pool.getConnection(); Connection b = pool.getConnection()) {
                assertTrue(((PooledConnection) a).delegate() == physical.proxy
                        || ((PooledConnection) b).delegate() == physical.proxy,
                        "the settled connection never came back into use");
            }
            assertTrue(reset.settled);
            assertEquals(2, source.handedOut().size(), "nothing was retired or opened anew");
        }
    }

    @Test
    void aBorrowerWithNothingElseWaitsForTheAnswer() throws Exception {
        StubDataSource source = new StubDataSource();
        Deferred reset = new Deferred();
        try (SeclumePool pool = new SeclumePool(source, settings(1))) {
            Connection first = pool.getConnection();
            StubDataSource.StubConnection physical = source.handedOut().getFirst();
            physical.sessionReset = reset;
            try (Statement used = first.createStatement()) {
                assertFalse(used.isClosed());
            }
            first.close();

            Thread.ofVirtual().start(() -> {
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                reset.answer.countDown();
            });
            try (Connection second = pool.getConnection()) {
                assertTrue(reset.settled, "lent before its reset was confirmed");
                assertSame(physical.proxy, ((PooledConnection) second).delegate());
            }
        }
    }

    @Test
    void aRefusedResetRetiresTheConnection() throws Exception {
        StubDataSource source = new StubDataSource();
        Deferred reset = new Deferred();
        reset.refuse = true;
        try (SeclumePool pool = new SeclumePool(source, settings(1))) {
            Connection first = pool.getConnection();
            StubDataSource.StubConnection physical = source.handedOut().getFirst();
            physical.sessionReset = reset;
            try (Statement used = first.createStatement()) {
                assertFalse(used.isClosed());
            }
            first.close();
            reset.answer.countDown();

            try (Connection second = pool.getConnection()) {
                assertNotSame(physical.proxy, ((PooledConnection) second).delegate(),
                        "a session whose reset was refused was lent again");
            }
            assertEquals(2, source.handedOut().size());
        }
    }

    /** The pool closed while a reset is on its way back: the connection is closed unread. */
    @Test
    void closingThePoolClosesAConnectionWhoseResetIsOwed() throws Exception {
        StubDataSource source = new StubDataSource();
        Deferred reset = new Deferred();
        SeclumePool pool = new SeclumePool(source, settings(1));
        Connection first = pool.getConnection();
        StubDataSource.StubConnection physical = source.handedOut().getFirst();
        physical.sessionReset = reset;
        try (Statement used = first.createStatement()) {
            assertFalse(used.isClosed());
        }
        first.close();

        pool.close();
        assertTrue(physical.closed.get(), "the connection outlived the pool");
        assertFalse(reset.settled, "the answer was waited for on close");
    }

    /**
     * The pool closed while a borrower is reading a connection's reset
     * answer: the session is not closed under that read, and the borrower,
     * finding the pool closed, does not get the connection.
     */
    @Test
    void closingThePoolLeavesAResetBeingReadToItsBorrower() throws Exception {
        StubDataSource source = new StubDataSource();
        Deferred reset = new Deferred();
        SeclumePool pool = new SeclumePool(source, settings(1));
        Connection first = pool.getConnection();
        StubDataSource.StubConnection physical = source.handedOut().getFirst();
        physical.sessionReset = reset;
        try (Statement used = first.createStatement()) {
            assertFalse(used.isClosed());
        }
        first.close();

        java.util.concurrent.atomic.AtomicReference<Throwable> borrowed =
                new java.util.concurrent.atomic.AtomicReference<>();
        Thread borrower = Thread.ofVirtual().start(() -> {
            try (Connection c = pool.getConnection()) {
                borrowed.set(new AssertionError("lent from a closed pool: " + c));
            } catch (SQLException expected) {
                borrowed.set(expected);
            }
        });
        Thread.sleep(150);                                  // in settleReset, waiting
        Thread closer = Thread.ofVirtual().start(pool::close);
        Thread.sleep(150);
        assertFalse(physical.closed.get(), "closed under the read of its reset answer");
        reset.answer.countDown();
        closer.join(10_000);
        borrower.join(10_000);
        assertFalse(closer.isAlive(), "close() did not return");
        assertTrue(borrowed.get() instanceof SQLException, String.valueOf(borrowed.get()));
        await(physical.closed::get);
    }

    /**
     * The reset is settled by the borrower that takes the connection - no
     * thread of its own per return.
     */
    @Test
    void theBorrowerSettlesTheResetItself() throws Exception {
        StubDataSource source = new StubDataSource();
        Deferred reset = new Deferred();
        reset.answer.countDown();                         // answered at once
        try (SeclumePool pool = new SeclumePool(source, settings(1))) {
            Connection first = pool.getConnection();
            source.handedOut().getFirst().sessionReset = reset;
            try (Statement used = first.createStatement()) {
                assertFalse(used.isClosed());
            }
            first.close();
            assertTrue(reset.owed, "the reset was settled on return");
            try (Connection second = pool.getConnection()) {
                assertTrue(reset.settled, "lent before its reset was confirmed");
                assertFalse(second.isClosed());
            }
        }
    }

    private static void await(java.util.function.BooleanSupplier condition)
            throws InterruptedException {
        long until = System.nanoTime() + 5_000_000_000L;
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > until) {
                throw new AssertionError("not reached in time");
            }
            Thread.sleep(5);
        }
    }
}
