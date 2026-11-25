package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;

/**
 * A driver whose setSessionContext threw an Error - a StackOverflowError, an
 * AssertionError - left the entry IN_USE: the cleanup caught only
 * SQLException and RuntimeException, and a pool of one was empty for good.
 */
class SessionContextErrorTest {

    private static final class Source implements DataSource {
        final AtomicInteger opened = new AtomicInteger();
        final AtomicBoolean fail = new AtomicBoolean(true);

        @Override
        public Connection getConnection() {
            opened.incrementAndGet();
            AtomicBoolean closed = new AtomicBoolean();
            space.seclume.SessionContext context = (name, value) -> {
                if (fail.get()) {
                    throw new AssertionError("the driver broke (decoy)");
                }
            };
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, (self, method, args) ->
                            switch (method.getName()) {
                                case "isWrapperFor" -> args[0] == space.seclume.SessionContext.class;
                                case "unwrap" -> context;
                                case "isClosed" -> closed.get();
                                case "close" -> {
                                    closed.set(true);
                                    yield null;
                                }
                                case "isValid", "getAutoCommit" -> !closed.get();
                                case "hashCode" -> System.identityHashCode(self);
                                case "equals" -> self == args[0];
                                default -> method.getReturnType() == boolean.class ? false
                                        : method.getReturnType() == int.class ? 0 : null;
                            });
        }

        @Override
        public Connection getConnection(String user, String password) {
            throw new UnsupportedOperationException();
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
        public <T> T unwrap(Class<T> type) {
            return null;
        }

        @Override
        public boolean isWrapperFor(Class<?> type) {
            return false;
        }
    }

    @Test
    void anErrorFromTheDriverDoesNotKeepTheEntry() throws SQLException {
        Source source = new Source();
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(1);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        settings.setSessionContext(() -> Map.of("app.tenant_id", "acme"));
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            assertThrows(AssertionError.class, pool::getConnection);
            source.fail.set(false);
            try (Connection next = pool.getConnection()) {
                assertTrue(next.isValid(1), "the pool of one was empty for good");
            }
        }
    }
}
