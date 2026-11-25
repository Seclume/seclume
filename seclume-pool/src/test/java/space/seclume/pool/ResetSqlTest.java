package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;

/**
 * A pool over a driver without a session reset of its own handed one
 * borrower's SET ROLE, set_config and temporary tables to the next. A
 * configured reset SQL runs on every used connection's return.
 */
class ResetSqlTest {

    /** A foreign driver's connections: no SessionReset, every executed SQL recorded. */
    private static final class Source implements DataSource {
        final List<String> executed = new CopyOnWriteArrayList<>();
        final AtomicInteger opened = new AtomicInteger();
        volatile boolean resetFails;

        @Override
        public Connection getConnection() {
            opened.incrementAndGet();
            AtomicBoolean closed = new AtomicBoolean();
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, (self, method, args) ->
                            switch (method.getName()) {
                                case "createStatement" -> statement();
                                case "isWrapperFor" -> false;
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

        private Statement statement() {
            return (Statement) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Statement.class}, (self, method, args) ->
                            switch (method.getName()) {
                                case "execute" -> {
                                    String sql = (String) args[0];
                                    if (resetFails && sql.startsWith("DISCARD")) {
                                        throw new SQLException("cannot reset (decoy)");
                                    }
                                    executed.add(sql);
                                    yield false;
                                }
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

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(1);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        settings.setValidationBypassWindow(Duration.ofMinutes(5));
        settings.setResetSql("DISCARD ALL");
        return settings;
    }

    @Test
    void aUsedConnectionIsResetOnItsReturn() throws SQLException {
        Source source = new Source();
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            try (Connection first = pool.getConnection();
                 Statement statement = first.createStatement()) {
                statement.execute("SET ROLE admin");
            }
            assertEquals(List.of("SET ROLE admin", "DISCARD ALL"), source.executed);
            try (Connection second = pool.getConnection()) {
                assertTrue(second.isValid(1));
            }
            assertEquals(1, source.opened.get(), "the reset connection was lent again");
        }
    }

    @Test
    void aResetThatFailsClosesTheConnection() throws SQLException {
        Source source = new Source();
        source.resetFails = true;
        try (SeclumePool pool = new SeclumePool(source, settings())) {
            try (Connection first = pool.getConnection();
                 Statement statement = first.createStatement()) {
                statement.execute("SET ROLE admin");
            }
            try (Connection second = pool.getConnection()) {
                assertTrue(second.isValid(1));
            }
            assertEquals(2, source.opened.get(), "the unreset connection was lent again");
        }
    }
}
