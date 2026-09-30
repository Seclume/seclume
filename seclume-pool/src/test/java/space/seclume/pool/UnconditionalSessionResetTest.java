package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.SessionReset;

/** SEC-01: SQL heuristics cannot see a stored procedure's session side effects. */
class UnconditionalSessionResetTest {
    private static final class Reset implements SessionReset {
        int calls;
        String tenant;
        int failure;

        @Override
        public boolean sessionStateChanged() {
            return false; // Hidden side effects never reached the SQL tracker.
        }

        @Override
        public boolean resetSessionState() throws SQLException {
            calls++;
            if (failure == 1) {
                return false;
            }
            if (failure == 2) {
                throw new SQLException("reset failed");
            }
            if (failure == 3) {
                throw new IllegalStateException("reset failed unchecked");
            }
            tenant = null;
            return true;
        }
    }

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(1);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        settings.setShutdownTimeout(Duration.ZERO);
        return settings;
    }

    @Test
    void hiddenTenantIsRemovedBeforeTheNextBorrow() throws Exception {
        StubDataSource source = new StubDataSource();
        Reset reset = new Reset();
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            Connection first = pool.getConnection();
            StubDataSource.StubConnection physical = source.handedOut().getFirst();
            physical.sessionReset = reset;
            try (Statement statement = first.createStatement()) {
                assertFalse(statement.isClosed());
            }
            reset.tenant = "tenant-a";
            first.close();
            first.close();
            assertEquals(1, reset.calls, "one reset per returned borrow");
            try (Connection second = pool.getConnection()) {
                assertSame(physical.proxy, ((PooledConnection) second).delegate());
                assertNull(reset.tenant);
            }
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3})
    void unsuccessfulResetRetiresTheConnection(int failure) throws Exception {
        StubDataSource source = new StubDataSource();
        Reset reset = new Reset();
        reset.failure = failure;
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            Connection first = pool.getConnection();
            StubDataSource.StubConnection physical = source.handedOut().getFirst();
            physical.sessionReset = reset;
            try (Statement statement = first.createStatement()) {
                assertFalse(statement.isClosed());
            }
            first.close();
            assertEquals(1, reset.calls);
            assertTrue(physical.closed.get());
            try (Connection next = pool.getConnection()) {
                assertNotSame(physical.proxy, ((PooledConnection) next).delegate());
            }
        }
    }

    @Test
    void unwrappedAccessAlsoRequiresReset() throws Exception {
        StubDataSource source = new StubDataSource();
        Reset reset = new Reset();
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            Connection handle = pool.getConnection();
            source.handedOut().getFirst().sessionReset = reset;
            assertSame(reset, handle.unwrap(SessionReset.class));
            reset.tenant = "tenant-a";
            handle.close();
            assertNull(reset.tenant);
            assertEquals(1, reset.calls);
            assertThrows(SQLException.class, () -> handle.unwrap(SessionReset.class));
        }
    }

    @Test
    void migrationPreservesStateUntilTheAdoptedBorrowIsReturned() throws Exception {
        StubDataSource source = new StubDataSource();
        Reset reset = new Reset();
        try (SeclumePool sender = new SeclumePool(source, settings());
             SeclumePool receiver = new SeclumePool(new StubDataSource(), settings())) {
            Connection handle = sender.getConnection();
            StubDataSource.StubConnection physical = source.handedOut().getFirst();
            physical.sessionReset = reset;
            reset.tenant = "migrating-tenant";
            handle.setAutoCommit(false);
            Connection detached = sender.detach(handle);
            handle.close(); // A detached handle must not reset the migrated session.
            assertSame(physical.proxy, detached);
            assertFalse(physical.closed.get());
            assertEquals(0, reset.calls);
            assertEquals(0, physical.rollbacks.get());
            try (Connection adopted = receiver.adopt(detached)) {
                assertFalse(adopted.getAutoCommit());
                assertEquals("migrating-tenant", reset.tenant);
                assertEquals(0, reset.calls);
            }
            assertEquals(1, physical.rollbacks.get());
            assertEquals(1, reset.calls);
            assertNull(reset.tenant);
            assertFalse(physical.closed.get());
        }
    }
}
