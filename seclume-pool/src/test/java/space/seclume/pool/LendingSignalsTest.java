package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * What the pool tells the driver connection and does to it around a borrow,
 * checked without a database: that it is lent and that it is back, that a
 * statement closed through the pool closes the driver's, that the reset
 * commits only outside auto-commit, and that a parked connection found dead
 * is replaced by the next one parked rather than by a new login.
 */
@Timeout(30)
class LendingSignalsTest {

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(3);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        return settings;
    }

    @Test
    void theDriverIsToldWhenItIsLentAndWhenItIsBack() throws Exception {
        StubDataSource source = new StubDataSource();
        source.beforeReturn(stub -> stub.fronted = true);
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            try (Connection first = pool.getConnection()) {
                assertTrue(first.isValid(1));
                assertEquals(List.of(true), source.handedOut().get(0).lentSaid);
            }
            assertEquals(List.of(true, false), source.handedOut().get(0).lentSaid);
            try (Connection again = pool.getConnection()) {
                assertTrue(again.isValid(1));
                assertEquals(1, source.openedCount(), "the parked connection was not lent again");
                assertEquals(List.of(true, false, true), source.handedOut().get(0).lentSaid);
            }
        }
    }

    @Test
    void aStatementClosedThroughThePoolClosesTheDrivers() throws Exception {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings());
             Connection handle = pool.getConnection()) {
            Statement statement = handle.createStatement();
            StubDataSource.StubStatement behind =
                    source.handedOut().get(0).statementsHandedOut.get(0);
            assertFalse(behind.closed.get());
            statement.close();
            assertTrue(behind.closed.get(), "the driver's statement is still open");
            assertFalse(source.handedOut().get(0).closed.get());
        }
    }

    @Test
    void theResetCommitsOnlyOutsideAutoCommit() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setResetSql("reset all");
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            try (Connection handle = pool.getConnection();
                 Statement statement = handle.createStatement()) {
                assertTrue(handle.getAutoCommit());
                assertFalse(statement.isClosed());
            }
            StubDataSource.StubConnection stub = source.handedOut().get(0);
            assertTrue(stub.statementsHandedOut.size() >= 2, "the reset SQL did not run");
            assertEquals(0, stub.commits.get(), "a commit in auto-commit mode");
        }
    }

    @Test
    void aDeadParkedConnectionIsReplacedByTheNextParkedOne() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setValidationBypassWindow(Duration.ZERO);       // checked on every borrow
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            Connection a = pool.getConnection();
            Connection b = pool.getConnection();
            b.close();                                  // the one the pool looks at first
            a.close();
            StubDataSource.StubConnection dead = source.handedOut().get(1);
            dead.valid = false;
            try (Connection next = pool.getConnection()) {
                assertTrue(next.isValid(1));
            }
            assertTrue(dead.closed.get(), "the dead connection was not retired");
            assertEquals(2, source.openedCount(),
                    "a new login was made while a live connection was parked");
            assertSame(Boolean.FALSE, source.handedOut().get(0).closed.get());
        }
    }
}
