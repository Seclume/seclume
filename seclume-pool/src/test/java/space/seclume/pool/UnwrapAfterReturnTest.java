package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * What unwrap() returns is the driver's own connection, and it outlived the
 * borrow: kept by the application, it ran in whatever session the pool lent
 * the connection to next. Back in the pool, the driver connection refuses
 * every call that reaches the server; the pool's own checks between borrows
 * still pass, and the next borrow works as always.
 */
@Timeout(120)
class UnwrapAfterReturnTest {

    static java.util.List<SessionContextTest.Db> databases() {
        return SessionContextTest.databases();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void theDriverConnectionRefusesOnceItIsBackInThePool(SessionContextTest.Db db)
            throws Exception {
        PoolSettings settings = SessionContextTest.settings();
        // Validated on every borrow: the pool's own check of a parked
        // connection must not be what the refusal refuses.
        settings.setValidationBypassWindow(java.time.Duration.ZERO);
        try (SeclumePool pool = new SeclumePool(
                new SessionContextTest.UrlSource(SessionContextTest.url(db)), settings)) {
            Connection kept;
            try (Connection borrowed = pool.getConnection()) {
                kept = (Connection) borrowed.unwrap(space.seclume.internal.jdbc.Fronted.class);
                try (Statement during = kept.createStatement()) {
                    assertTrue(during.execute(db.read()), "usable during the borrow");
                }
            }
            SQLException refused = assertThrows(SQLException.class, kept::createStatement);
            assertEquals("08003", refused.getSQLState());
            assertTrue(refused.getMessage().contains("back in its pool"), refused.getMessage());
            assertThrows(SQLException.class, () -> kept.prepareStatement(db.read()));
            assertThrows(SQLException.class, kept::commit);
            // What it knows of itself it may still say: nothing goes to the server.
            kept.getAutoCommit();
            kept.getTransactionIsolation();

            try (Connection next = pool.getConnection();
                 Statement statement = next.createStatement()) {
                assertTrue(statement.execute(db.read()), "the next borrow works as always");
            }
        }
    }
}
