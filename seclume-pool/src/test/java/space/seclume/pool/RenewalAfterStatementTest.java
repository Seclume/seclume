package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * A broken connection is renewed quietly only where nothing can be lost. A
 * borrow that had handed out a statement could still be renewed - but
 * {@code select app.enter_tenant(42)} sets a role or a tenant the driver never
 * sees, and the renewed connection ran the borrower's next statement as the
 * login role. Once a statement was handed out, closed or not, the failure
 * goes through.
 */
class RenewalAfterStatementTest {

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setName("renew-after-statement");
        settings.setMaximumPoolSize(4);
        settings.setConnectionTimeout(Duration.ofSeconds(5));
        settings.setValidationBypassWindow(Duration.ofMinutes(5));
        return settings;
    }

    @Test
    void aBorrowThatHandedOutAStatementIsNotRenewed() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings());
             Connection connection = pool.getConnection()) {
            Statement enter = connection.createStatement();      // select app.enter_tenant(42)
            enter.close();
            source.handedOut().get(0).broken = true;
            assertThrows(SQLException.class, connection::createStatement);
            assertEquals(1, source.openedCount(), "renewed after a statement had run");
            assertEquals(0, pool.statistics().renewed());
        }
    }

    @Test
    void aBorrowThatHasDoneNothingIsRenewed() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings());
             Connection connection = pool.getConnection()) {
            source.handedOut().get(0).broken = true;
            assertNotNull(connection.createStatement(), "the control");
            assertEquals(2, source.openedCount());
        }
    }
}
