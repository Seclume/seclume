package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;

/**
 * A credential whose end lies in the past - Key Vault hands such a secret
 * out all the same - made the pool see every connection as expired: a new
 * login for every borrow. The provider answers "no end" for it (see
 * AzureKeyVaultSecretProvider.stillMeant), and a hundred borrows are one
 * login. The contrast: the same past instant taken as the end is a login
 * per borrow, which is what this guards against.
 */
class PastCredentialExpiryTest {

    private static final class Counting implements DataSource {
        final AtomicInteger opened = new AtomicInteger();

        @Override
        public Connection getConnection() {
            opened.incrementAndGet();
            AtomicBoolean gone = new AtomicBoolean();
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, (self, method, args) ->
                            switch (method.getName()) {
                                case "isClosed" -> gone.get();
                                case "close" -> {
                                    gone.set(true);
                                    yield null;
                                }
                                case "isValid", "getAutoCommit" -> !gone.get();
                                case "isWrapperFor" -> false;
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

    private static int loginsFor(Supplier<Instant> expiry) throws Exception {
        Counting source = new Counting();
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(1);
        settings.setMinimumIdle(0);
        settings.setConnectionTimeout(Duration.ofSeconds(2));
        settings.setValidationBypassWindow(Duration.ofMinutes(5));
        settings.setCredentialExpiry(expiry);
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            for (int borrow = 0; borrow < 100; borrow++) {
                try (Connection connection = pool.getConnection()) {
                    assertTrue(!connection.isClosed());
                }
            }
        }
        return source.opened.get();
    }

    @Test
    void aHundredBorrowsWithAPastExpiryAreOneLogin() throws Exception {
        Instant past = Instant.parse("2026-01-01T00:00:00Z");
        // What the Key Vault provider answers for a secret whose exp has passed:
        // no end (AzurePastExpiryTest pins that down).
        assertEquals(1, loginsFor(() -> null), "a login per borrow");
        assertTrue(loginsFor(() -> past) > 1,
                "the contrast: a past instant taken as the end renews every connection");
    }
}
