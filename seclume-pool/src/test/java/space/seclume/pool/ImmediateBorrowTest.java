package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.SessionReset;

/**
 * {@link SeclumePool#getConnectionIfReady}: a connection lent without
 * waiting, or none - and every rule of an ordinary borrow kept. Above all
 * the one this pool exists for: no session goes out before the reset of its
 * last borrow is confirmed. Here that confirmation is only read when it has
 * already arrived; otherwise the connection stays for a borrow that may wait.
 */
@Timeout(30)
class ImmediateBorrowTest {

    /** A reset answered when the test says so, and refused if it says that. */
    private static final class Answered implements SessionReset {
        final AtomicBoolean arrived = new AtomicBoolean();
        volatile boolean owed;
        volatile boolean settled;
        volatile boolean refuse;
        volatile int settles;

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
            return !owed || arrived.get();
        }

        @Override
        public void settleReset() throws SQLException {
            settles++;
            if (!arrived.get()) {
                throw new AssertionError("settled before its answer arrived: that read would wait");
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

    /** A connection used and given back, owing the given reset. */
    private static StubDataSource.StubConnection usedAndReturned(SeclumePool pool, StubDataSource source,
                                                                 Answered reset) throws SQLException {
        Connection first = pool.getConnection();
        StubDataSource.StubConnection physical = source.handedOut().getLast();
        physical.sessionReset = reset;
        try (Statement used = first.createStatement()) {
            assertFalse(used.isClosed());
        }
        first.close();
        assertTrue(reset.owed, "the reset was sent on return");
        return physical;
    }

    @Test
    void anEmptyPoolLendsNothingAndOpensNothing() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings(2))) {
            assertNull(pool.getConnectionIfReady());
            assertEquals(0, source.openedCount(), "opening one is a wait");
        }
    }

    @Test
    void aFreeConnectionIsLentAtOnceAndGoesBackAsUsual() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings(2))) {
            pool.getConnection().close();
            try (Connection lent = pool.getConnectionIfReady()) {
                assertNotNull(lent);
                assertSame(source.handedOut().getFirst().proxy, ((PooledConnection) lent).delegate());
                assertNull(pool.getConnectionIfReady(), "the only one is out");
            }
            assertNotNull(pool.getConnectionIfReady(), "and back after the close");
        }
    }

    @Test
    void aResetWhoseAnswerHasNotArrivedIsNotWaitedForAndNotSkipped() throws SQLException {
        StubDataSource source = new StubDataSource();
        Answered reset = new Answered();
        try (SeclumePool pool = new SeclumePool(source, settings(1))) {
            StubDataSource.StubConnection physical = usedAndReturned(pool, source, reset);

            assertNull(pool.getConnectionIfReady(), "lent with its reset unconfirmed, or waited for it");
            assertEquals(0, reset.settles);

            reset.arrived.set(true);
            try (Connection lent = pool.getConnectionIfReady()) {
                assertNotNull(lent, "the connection was lost on the way");
                assertTrue(reset.settled, "lent before its reset was confirmed");
                assertSame(physical.proxy, ((PooledConnection) lent).delegate());
            }
        }
    }

    @Test
    void aRefusedResetIsNotLentAndTheConnectionIsRetired() throws SQLException {
        StubDataSource source = new StubDataSource();
        Answered reset = new Answered();
        reset.refuse = true;
        try (SeclumePool pool = new SeclumePool(source, settings(1))) {
            StubDataSource.StubConnection physical = usedAndReturned(pool, source, reset);
            reset.arrived.set(true);

            assertNull(pool.getConnectionIfReady());
            assertTrue(physical.closed.get(), "a session whose reset was refused stayed in the pool");
            try (Connection next = pool.getConnection()) {
                assertFalse(((PooledConnection) next).delegate() == physical.proxy);
            }
            assertEquals(2, source.openedCount());
        }
    }

    @Test
    void aConnectionDueForValidationIsLeftToAnOrdinaryBorrow() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings(1);
        settings.setValidationBypassWindow(Duration.ofMillis(1));
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            pool.getConnection().close();
            StubDataSource.StubConnection physical = source.handedOut().getFirst();
            Thread.sleep(20);

            assertNull(pool.getConnectionIfReady(), "validation is a round trip");
            assertEquals(0, physical.validations.get());
            try (Connection validated = pool.getConnection()) {
                assertSame(physical.proxy, ((PooledConnection) validated).delegate(),
                        "the connection put back is still the pool's");
                assertEquals(1, physical.validations.get(), "the ordinary borrow asked");
            }
        }
    }

    @Test
    void aClosedPoolSaysSo() throws SQLException {
        SeclumePool pool = new SeclumePool(new StubDataSource(), settings(1));
        pool.close();
        assertThrows(SQLException.class, pool::getConnectionIfReady);
    }
}
