package space.seclume.crac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;
import space.seclume.secret.SecretScope;

/**
 * The checkpoint barrier (N6): it waits for borrowed connections and open
 * secrets, and refuses the checkpoint when they do not go away.
 */
@Timeout(60)
class QuiesceTest {

    /** Connections that do nothing but know whether they were closed. */
    private static final class Source implements DataSource {

        @Override
        public Connection getConnection() {
            AtomicBoolean closed = new AtomicBoolean();
            return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                    new Class<?>[] {Connection.class}, (self, method, args) -> switch (method.getName()) {
                        case "close" -> {
                            closed.set(true);
                            yield null;
                        }
                        case "isClosed" -> closed.get();
                        case "isValid" -> !closed.get();
                        case "getAutoCommit" -> true;
                        case "isReadOnly" -> false;
                        case "getTransactionIsolation" -> Connection.TRANSACTION_READ_COMMITTED;
                        case "hashCode" -> System.identityHashCode(self);
                        case "equals" -> self == args[0];
                        case "toString" -> "QuiesceTest.Connection";
                        default -> zeroOf(method.getReturnType());
                    });
        }

        /** What a method returning {@code type} returns when it has nothing to say. */
        private static Object zeroOf(Class<?> type) {
            if (type == boolean.class) {
                return false;
            }
            if (type == int.class) {
                return 0;
            }
            if (type == long.class) {
                return 0L;
            }
            return null;
        }

        @Override
        public Connection getConnection(String user, String password) throws SQLException {
            throw new SQLException("not used");
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
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException();
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

    private static SeclumePool pool() {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(2);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        return new SeclumePool(new Source(), settings);
    }

    @Test
    void aQuietPoolIsReadyAtOnce() throws Exception {
        try (SeclumePool pool = pool()) {
            pool.getConnection().close();
            SeclumeCrac.quiesce(pool, 2000);
            assertEquals(0, pool.activeCount());
            assertEquals(0, pool.idleCount(), "the idle connection survived the checkpoint");
            pool.resume();
        }
    }

    @Test
    void aBorrowedConnectionHoldsTheCheckpointUntilItComesBack() throws Exception {
        try (SeclumePool pool = pool()) {
            Connection borrowed = pool.getConnection();
            Thread returner = Thread.ofPlatform().start(() -> {
                try {
                    Thread.sleep(300);
                    borrowed.close();
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
            long start = System.nanoTime();
            SeclumeCrac.quiesce(pool, 5000);
            assertTrue(System.nanoTime() - start >= Duration.ofMillis(250).toNanos(),
                    "the checkpoint did not wait for the borrowed connection");
            returner.join();
            pool.resume();
        }
    }

    @Test
    void aConnectionThatNeverComesBackRefusesTheCheckpoint() throws Exception {
        try (SeclumePool pool = pool()) {
            Connection borrowed = pool.getConnection();
            try {
                IllegalStateException refused = assertThrows(IllegalStateException.class,
                        () -> SeclumeCrac.quiesce(pool, 300));
                assertTrue(refused.getMessage().contains("1 connection"), refused.getMessage());
            } finally {
                borrowed.close();
            }
        }
    }

    @Test
    void anOpenSecretRefusesTheCheckpoint() throws Exception {
        try (SeclumePool pool = pool(); SecretScope held = SecretScope.allocate(16)) {
            assertEquals(16, held.segment().byteSize());
            IllegalStateException refused = assertThrows(IllegalStateException.class,
                    () -> SeclumeCrac.quiesce(pool, 300));
            assertTrue(refused.getMessage().contains("secret"), refused.getMessage());
        }
    }
}
