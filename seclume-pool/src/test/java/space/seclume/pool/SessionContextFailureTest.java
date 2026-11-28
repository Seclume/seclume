package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Two of the pool's audit fixes, on stub connections. A session context
 * resolver that throws - a request without a tenant - lost the connection it
 * was asked for: two such requests emptied a pool of two. And a login under
 * way while the secret was rotated was kept and lent with the old secret.
 */
@Timeout(60)
class SessionContextFailureTest {

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(2);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        return settings;
    }

    @Test
    void aResolverThatThrowsGivesTheConnectionBack() throws SQLException {
        AtomicInteger failures = new AtomicInteger(3);
        PoolSettings settings = settings();
        settings.setSessionContext(() -> {
            if (failures.getAndDecrement() > 0) {
                throw new IllegalStateException("no tenant for this request (decoy)");
            }
            return Map.of();
        });
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            for (int i = 0; i < 3; i++) {
                IllegalStateException thrown = assertThrows(IllegalStateException.class,
                        pool::getConnection);
                assertEquals("no tenant for this request (decoy)", thrown.getMessage(),
                        "the resolver's own exception reaches the caller");
            }
            try (Connection fine = pool.getConnection(); Connection second = pool.getConnection()) {
                assertTrue(fine.isValid(1) && second.isValid(1),
                        "the pool of two still lends two");
            }
            assertTrue(source.openedCount() <= 2, "opened " + source.openedCount());
        }
    }

    /** A source that rotates the pool's secret while its first login is under way. */
    private static final class RotatingSource implements DataSource {
        final StubDataSource stub = new StubDataSource();
        final AtomicReference<SeclumePool> pool = new AtomicReference<>();
        final AtomicInteger logins = new AtomicInteger();
        final boolean rotate;

        RotatingSource(boolean rotate) {
            this.rotate = rotate;
        }

        @Override
        public Connection getConnection() throws SQLException {
            if (rotate && logins.getAndIncrement() == 0) {
                pool.get().rotateSecret(false);     // while this login reads the secret
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
    void aLoginDuringRotationIsRetiredOnReturn() throws SQLException {
        RotatingSource source = new RotatingSource(true);
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            source.pool.set(pool);
            try (Connection first = pool.getConnection()) {
                assertTrue(first.isValid(1));
            }
            assertTrue(source.stub.handedOut().get(0).closed.get(),
                    "the connection logged in during the rotation went back into the pool");
            try (Connection next = pool.getConnection()) {
                assertTrue(next.isValid(1));
            }
            assertEquals(2, source.stub.openedCount(), "the next borrow logs in anew");
        }
    }

    @Test
    void withoutRotationTheConnectionIsKept() throws SQLException {
        RotatingSource source = new RotatingSource(false);
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            source.pool.set(pool);
            try (Connection first = pool.getConnection()) {
                assertTrue(first.isValid(1));
            }
            try (Connection again = pool.getConnection()) {
                assertTrue(again.isValid(1));
            }
            assertEquals(1, source.stub.openedCount(), "the control");
        }
    }
}
