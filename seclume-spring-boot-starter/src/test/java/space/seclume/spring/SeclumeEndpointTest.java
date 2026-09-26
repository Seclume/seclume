package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;
import space.seclume.tck.TestHosts;

/** {@code /actuator/seclume} against a real encrypted connection. */
@Timeout(60)
class SeclumeEndpointTest {

    @Test
    @SuppressWarnings("unchecked")
    void theReportSaysHowTheDataSourceIsSecured() throws Exception {
        Path secret = null;
        for (Path candidate : List.of(Path.of(".local-pgtls-password"),
                Path.of("..", ".local-pgtls-password"))) {
            if (Files.exists(candidate)) {
                secret = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(secret != null, "no .local-pgtls-password");
        String host = TestHosts.database();
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, 5433), 2000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL with TLS on " + host);
        }
        String url = "jdbc:seclume:postgresql://" + host + ":5433/seclume_test?user=seclume_test"
                + "&tls=require&tlsStack=seclume&provider=file&path="
                + secret.toString().replace('\\', '/');
        PoolSettings settings = new PoolSettings();
        settings.setName("orders");
        settings.setMaximumPoolSize(2);
        try (SeclumePool pool = new SeclumePool(new UrlSource(url), settings)) {
            Map<String, Object> report = new SeclumeEndpoint(List.of(pool)).report();
            assertTrue(String.valueOf(report.get("version")).matches("\\d+\\.\\d+.*|development"),
                    "no version: " + report.get("version"));
            Map<String, Object> source = (Map<String, Object>)
                    ((Map<String, Object>) report.get("dataSources")).get("orders");
            assertTrue(String.valueOf(source.get("authentication")).toLowerCase().contains("scram"),
                    source.toString());
            assertTrue(String.valueOf(source.get("tls")).contains("TLSv1.3"), source.toString());
            assertTrue(String.valueOf(source.get("tls")).contains("seclume"), source.toString());
            Map<String, Object> certificate = (Map<String, Object>) source.get("serverCertificate");
            assertTrue(certificate.get("expires").toString().matches("\\d{4}-.*"),
                    source.toString());
            Map<String, Object> capacity = (Map<String, Object>) source.get("serverCapacity");
            assertTrue(capacity.get("allowed") instanceof Integer, source.toString());
            assertTrue(!report.toString().toLowerCase().contains("password="),
                    "a password setting reached the report: " + report);
        }
    }

    /** A pool wants a {@code DataSource}; a driver wants a URL. */
    private record UrlSource(String url) implements DataSource {

        @Override
        public Connection getConnection() throws SQLException {
            return DriverManager.getConnection(url);
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
            return Logger.getLogger("seclume.test");
        }

        @Override
        public <T> T unwrap(Class<T> type) throws SQLException {
            throw new SQLException("not a wrapper for " + type);
        }

        @Override
        public boolean isWrapperFor(Class<?> type) {
            return false;
        }
    }
}
