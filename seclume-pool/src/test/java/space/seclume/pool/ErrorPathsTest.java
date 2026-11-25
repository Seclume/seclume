package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * An Error out of a connect - a StackOverflowError on a hostile answer - kept
 * the permit it had taken: after maximumPoolSize of them the pool could never
 * open a connection again. Every path that holds a permit gives it back on an
 * Error too.
 */
@Timeout(60)
class ErrorPathsTest {

    /** Throws StackOverflowError for its first {@code failures} logins, then lends stubs. */
    private static final class Overflowing implements DataSource {
        final StubDataSource stub = new StubDataSource();
        final AtomicInteger failures;

        Overflowing(int failures) {
            this.failures = new AtomicInteger(failures);
        }

        @Override
        public Connection getConnection() throws SQLException {
            if (failures.getAndDecrement() > 0) {
                throw new StackOverflowError("a hostile answer nested without end (decoy)");
            }
            return stub.getConnection();
        }

        @Override
        public Connection getConnection(String user, String password) throws SQLException {
            return getConnection();
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
        }

        @Override
        public void setLoginTimeout(int seconds) {
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() {
            return Logger.getGlobal();
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            throw new SQLException("not a wrapper");
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return false;
        }
    }

    @Test
    void aStackOverflowInConnectGivesThePermitBack() throws SQLException {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(2);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        Overflowing source = new Overflowing(3);
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            for (int i = 0; i < 3; i++) {
                assertThrows(StackOverflowError.class, pool::getConnection);
            }
            try (Connection one = pool.getConnection(); Connection two = pool.getConnection()) {
                assertTrue(one.isValid(1) && two.isValid(1),
                        "the permits the errors took were not given back");
            }
        }
    }
}
