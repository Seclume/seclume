package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.RoundTrips;
import space.seclume.tck.TestHosts;

/**
 * The pool gives every borrowed connection the session context of the moment
 * - the tenant a row-level security policy reads - and takes it off on return,
 * on all four. One connection in the pool, so every borrow is the same
 * session and anything left behind would show.
 */
@Timeout(120)
class SessionContextTest {

    private static final String AWKWARD = "a'b$seclume$c\"\\ü";

    record Db(String name, String url, String passwordFile, String key, String read,
              boolean free) {

        @Override
        public String toString() {
            return name;
        }
    }

    static List<Db> databases() {
        String host = TestHosts.database();
        return List.of(
                new Db("PostgreSQL", "jdbc:seclume:postgresql://" + TestHosts.postgres() + ":"
                        + TestHosts.postgresPort() + "/seclume_test?user=seclume_test&tls=off",
                        TestHosts.postgresPasswordFile(), "app.tenant_id",
                        "select nullif(current_setting('app.tenant_id', true), '')", true),
                new Db("MySQL", "jdbc:seclume:mysql://" + host + ":3307/seclume_test"
                        + "?user=seclume_test&tls=off&allowPublicKeyRetrieval=true",
                        ".local-mysql-password", "app.tenant_id", "select @app_tenant_id", true),
                new Db("SQL Server", "jdbc:seclume:sqlserver://" + host
                        + ":1433/master?user=sa&trustServerCertificate=true",
                        ".local-mssql-password", "app.tenant_id",
                        "select cast(session_context(N'app.tenant_id') as nvarchar(100))", false),
                new Db("Oracle", "jdbc:seclume:oracle://" + host + ":1521/FREEPDB1"
                        + "?user=seclume_test", ".local-oracle-password", "client_identifier",
                        "select sys_context('USERENV', 'CLIENT_IDENTIFIER') from dual", false));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void everyBorrowCarriesTheContextOfTheMomentAndNoMore(Db db) throws Exception {
        AtomicReference<String> tenant = new AtomicReference<>();
        PoolSettings settings = settings();
        settings.setSessionContext(() -> tenant.get() == null ? Map.of()
                : Map.of(db.key(), tenant.get()));
        try (SeclumePool pool = new SeclumePool(new UrlSource(url(db)), settings)) {
            tenant.set("42");
            assertEquals("42", read(pool, db));

            tenant.set(null);
            assertNull(read(pool, db), "the tenant of the last borrower is still there");

            // Borrowed with a tenant and given back untouched: the context is
            // still waiting to be sent, and must not be sent for the next one.
            tenant.set("7");
            pool.getConnection().close();
            tenant.set(null);
            assertNull(read(pool, db), "an unused borrow left its tenant behind");

            tenant.set(AWKWARD);
            assertEquals(AWKWARD, read(pool, db));

            if (db.free()) {
                tenant.set("9");
                try (Connection c = pool.getConnection()) {
                    long before = c.unwrap(RoundTrips.class).roundTrips();
                    assertEquals("9", ask(c, db.read()));
                    assertEquals(1, c.unwrap(RoundTrips.class).roundTrips() - before,
                            "the context cost a round trip of its own");
                }
            }
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void aContextTheServerCannotHoldStopsTheBorrow(Db db) throws Exception {
        PoolSettings settings = settings();
        settings.setSessionContext(() -> Map.of("not a name; drop table x", "1"));
        try (SeclumePool pool = new SeclumePool(new UrlSource(url(db)), settings)) {
            SQLException refused = assertThrows(SQLException.class, pool::getConnection);
            assertEquals("22023", refused.getSQLState(), refused.getMessage());
        }
        if (db.name().equals("Oracle")) {
            settings.setSessionContext(() -> Map.of("app.tenant_id", "1"));
            try (SeclumePool pool = new SeclumePool(new UrlSource(url(db)), settings)) {
                assertThrows(java.sql.SQLFeatureNotSupportedException.class, pool::getConnection);
            }
        }
    }

    private static String read(SeclumePool pool, Db db) throws SQLException {
        try (Connection c = pool.getConnection()) {
            return ask(c, db.read());
        }
    }

    private static String ask(Connection c, String sql) throws SQLException {
        try (Statement s = c.createStatement(); ResultSet rows = s.executeQuery(sql)) {
            rows.next();
            String value = rows.getString(1);
            return value == null || value.isEmpty() ? null : value;
        }
    }

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setName("context");
        settings.setMaximumPoolSize(1);
        settings.setConnectionTimeout(Duration.ofSeconds(10));
        return settings;
    }

    private static String url(Db db) {
        Path password = null;
        for (Path candidate : List.of(Path.of(db.passwordFile()), Path.of("..",
                db.passwordFile()))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no " + db.passwordFile());
        String address = db.url().substring(db.url().indexOf("//") + 2);
        String host = address.substring(0, address.indexOf(':'));
        int port = Integer.parseInt(address.substring(address.indexOf(':') + 1,
                address.indexOf('/')));
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no " + db.name() + " on " + host + ":" + port);
        }
        return db.url() + "&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/');
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
