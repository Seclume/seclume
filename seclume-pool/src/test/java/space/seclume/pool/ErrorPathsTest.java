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
        final java.util.function.Supplier<Error> error;

        Overflowing(int failures) {
            this(failures, () -> new StackOverflowError("a hostile answer nested without end (decoy)"));
        }

        Overflowing(int failures, java.util.function.Supplier<Error> error) {
            this.failures = new AtomicInteger(failures);
            this.error = error;
        }

        @Override
        public Connection getConnection() throws SQLException {
            if (failures.getAndDecrement() > 0) {
                throw error.get();
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

    /** A data source whose connections throw an Error when they are closed. */
    private static final class ClosesWithAnError {

        private ClosesWithAnError() {
        }

        static DataSource source() {
            StubDataSource stub = new StubDataSource();
            return (DataSource) java.lang.reflect.Proxy.newProxyInstance(
                    ErrorPathsTest.class.getClassLoader(), new Class<?>[] {DataSource.class},
                    (proxy, method, arguments) -> {
                        if (!method.getName().equals("getConnection")) {
                            return method.invoke(stub, arguments);
                        }
                        Connection real = stub.getConnection();
                        return java.lang.reflect.Proxy.newProxyInstance(
                                ErrorPathsTest.class.getClassLoader(),
                                new Class<?>[] {Connection.class}, (c, m, a) -> {
                                    if (m.getName().equals("close")) {
                                        throw new AssertionError("a driver's close failed (decoy)");
                                    }
                                    try {
                                        return m.invoke(real, a);
                                    } catch (java.lang.reflect.InvocationTargetException e) {
                                        throw e.getCause();
                                    }
                                });
                    });
        }
    }

    /**
     * An Error out of a driver's close - an AssertionError, a LinkageError -
     * left retire and ended the housekeeping thread, which caught
     * RuntimeException and StackOverflowError only: the pool never swept or
     * refilled again. Closing a connection for good swallows what the close
     * throws, and housekeeping carries on whatever a round throws.
     */
    @Test
    void housekeepingSweepsOnAfterACloseThrowsAnError() throws Exception {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(2);
        settings.setMinimumIdle(0);
        settings.setIdleTimeout(Duration.ofMillis(300));
        settings.setValidationTimeout(Duration.ofMillis(250));
        try (SeclumePool pool = new SeclumePool(ClosesWithAnError.source(), settings)) {
            try (Connection one = pool.getConnection(); Connection two = pool.getConnection()) {
                assertTrue(one.isValid(1) && two.isValid(1));
            }
            long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
            while (pool.statistics().total() > 0 && System.nanoTime() - deadline < 0) {
                Thread.sleep(50);
            }
            assertTrue(pool.statistics().total() == 0, "idle connections were left after the "
                    + "first close threw: " + pool.statistics());
        }
    }

    /**
     * Housekeeping caught RuntimeException and StackOverflowError only: any
     * other Error out of a driver - an AssertionError, a LinkageError, an
     * ExceptionInInitializerError - ended its thread, and the pool never
     * refilled or swept again. It carries on now.
     */
    @Test
    void housekeepingSurvivesAnError() throws Exception {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(2);
        settings.setMinimumIdle(1);
        settings.setValidationTimeout(Duration.ofMillis(250));
        Overflowing source = new Overflowing(3,
                () -> new AssertionError("a driver's own check failed (decoy)"));
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
            while (pool.statistics().idle() < 1 && System.nanoTime() - deadline < 0) {
                Thread.sleep(50);
            }
            assertTrue(source.failures.get() < 0, "the errors were never hit: " + source.failures);
            assertTrue(pool.statistics().idle() >= 1,
                    "after the errors housekeeping no longer refilled the pool");
        }
    }
}
