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
            SeclumeCrac.restored(pool);
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
            SeclumeCrac.restored(pool);
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

    /**
     * P4: from the barrier to the restore, a login that starts waits - its
     * secret would otherwise be made in the window before the image is
     * written, and end up in it.
     */
    @Test
    void aSecretRequestedAfterTheBarrierWaitsForTheRestore() throws Exception {
        try (SeclumePool pool = pool()) {
            SeclumeCrac.quiesce(pool, 2000);
            assertTrue(space.seclume.internal.Checkpoint.holding(), "nothing holds new secrets");
            java.util.concurrent.CountDownLatch made = new java.util.concurrent.CountDownLatch(1);
            Thread login = Thread.ofPlatform().start(() -> {
                try (SecretScope scope = SecretScope.allocate(16)) {
                    assertEquals(16, scope.segment().byteSize());
                    made.countDown();
                }
            });
            assertTrue(!made.await(300, java.util.concurrent.TimeUnit.MILLISECONDS),
                    "a secret was made while the checkpoint was being taken");
            SeclumeCrac.restored(pool);
            assertTrue(made.await(5, java.util.concurrent.TimeUnit.SECONDS),
                    "the restore did not let it through");
            login.join();
        }
    }

    /** A refused checkpoint lets new secrets through again. */
    @Test
    void aRefusedCheckpointHoldsNothingBack() throws Exception {
        try (SeclumePool pool = pool()) {
            Connection borrowed = pool.getConnection();
            try {
                assertThrows(IllegalStateException.class, () -> SeclumeCrac.quiesce(pool, 200));
                assertTrue(!space.seclume.internal.Checkpoint.holding(),
                        "a refused checkpoint kept new secrets waiting");
            } finally {
                borrowed.close();
            }
        }
    }
}
