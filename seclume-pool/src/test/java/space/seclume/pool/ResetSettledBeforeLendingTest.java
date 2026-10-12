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
 * is lent again - off the returning thread, while a borrower takes another
 * connection - and a refused one retires the connection.
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

    @Test
    void aConnectionWithItsResetOnTheWayIsNotLentUntilItIsAnswered() throws Exception {
        StubDataSource source = new StubDataSource();
        Deferred reset = new Deferred();
        try (SeclumePool pool = new SeclumePool(source, settings(2))) {
            Connection first = pool.getConnection();
            StubDataSource.StubConnection physical = source.handedOut().getFirst();
            physical.sessionReset = reset;
            try (Statement statement = first.createStatement()) {
                assertFalse(statement.isClosed());
            }
            first.close();                                   // returns at once
            assertTrue(reset.owed, "the reset was sent and is owed");

            // The borrower does not wait for that answer: it gets another one.
            try (Connection second = pool.getConnection()) {
                assertNotSame(physical.proxy, ((PooledConnection) second).delegate(),
                        "a connection whose reset was not confirmed was lent");
            }

            reset.answer.countDown();
            await(() -> reset.settled);
            // Now the first one is ready again, confirmed: with both taken at
            // once - the pool holds two - it has to be one of them.
            try (Connection a = pool.getConnection(); Connection b = pool.getConnection()) {
                assertTrue(((PooledConnection) a).delegate() == physical.proxy
                        || ((PooledConnection) b).delegate() == physical.proxy,
                        "the settled connection never came back into use");
            }
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
            first.createStatement().close();
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
            first.createStatement().close();
            first.close();
            reset.answer.countDown();

            try (Connection second = pool.getConnection()) {
                assertNotSame(physical.proxy, ((PooledConnection) second).delegate(),
                        "a session whose reset was refused was lent again");
            }
            assertEquals(2, source.handedOut().size());
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
