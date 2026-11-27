package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;

import space.seclume.Secured;
import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;

/**
 * The grade as the health check makes it: from what a pooled connection's
 * driver says about itself - through the pool's own connection wrapper, the
 * way an application's pool hands it out. TLS whose server nobody checked
 * (tls=prefer, tls=require) is a warning; with the server's certificate
 * checked (verify-full) there is none about TLS.
 */
class AssessmentWiringTest {

    /** Connections whose driver says TLS 1.3, the server checked or not. */
    private static final class Secure implements DataSource {
        private final Boolean serverAuthenticated;

        Secure(Boolean serverAuthenticated) {
            this.serverAuthenticated = serverAuthenticated;
        }

        @Override
        public Connection getConnection() {
            return (Connection) java.lang.reflect.Proxy.newProxyInstance(
                    Secure.class.getClassLoader(), new Class<?>[] {Connection.class, Secured.class},
                    (proxy, method, arguments) -> switch (method.getName()) {
                        case "isClosed", "isReadOnly" -> false;
                        case "isValid", "getAutoCommit" -> true;
                        case "getTransactionIsolation" -> Connection.TRANSACTION_READ_COMMITTED;
                        case "isWrapperFor" -> arguments[0] == Secured.class;
                        case "unwrap" -> arguments[0] == Secured.class ? proxy : null;
                        case "authenticationMethod" -> "scram-sha-256-plus";
                        case "tlsDescription" -> "TLSv1.3 TLS_AES_256_GCM_SHA384";
                        case "serverAuthenticated" -> serverAuthenticated;
                        case "serverCertificate" -> null;
                        case "hashCode" -> System.identityHashCode(proxy);
                        case "equals" -> proxy == arguments[0];
                        case "toString" -> "secured stub";
                        default -> null;
                    });
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            throw new SQLFeatureNotSupportedException("no password here");
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

    private static Map<String, Object> health(Boolean serverAuthenticated) {
        PoolSettings settings = new PoolSettings();
        settings.setName("graded");
        settings.setMaximumPoolSize(10);
        settings.setConnectionTimeout(java.time.Duration.ofSeconds(2));
        try (SeclumePool pool = new SeclumePool(new Secure(serverAuthenticated), settings)) {
            Health health = new SeclumePoolHealth(List.of(pool)).health();
            @SuppressWarnings("unchecked")
            Map<String, Object> ofThePool = (Map<String, Object>) health.getDetails().get("graded");
            return ofThePool;
        }
    }

    @Test
    void tlsWhoseServerNobodyCheckedIsAWarning() {
        for (Boolean unchecked : new Boolean[] {Boolean.FALSE, null}) {
            Map<String, Object> details = health(unchecked);
            assertEquals("warning", details.get("grade"), details.toString());
            assertTrue(String.valueOf(details).contains("not checked")
                    || String.valueOf(details).contains("tls"), details.toString());
        }
    }

    @Test
    void verifiedTlsGivesNoTlsWarning() {
        Map<String, Object> details = health(Boolean.TRUE);
        assertFalse(String.valueOf(details.get("findings")).contains("not checked"),
                details.toString());
        assertTrue(!"unknown - the driver cannot say how it is secured".equals(details.get("grade")),
                "the pool's wrapper hid the driver: " + details);
    }
}
