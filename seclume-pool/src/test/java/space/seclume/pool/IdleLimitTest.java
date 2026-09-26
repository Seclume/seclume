package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.ServerIdleLimit;
import space.seclume.tck.TestHosts;

/**
 * A server that closes idle sessions, and a pool that keeps its idle
 * connections below that limit without being told.
 *
 * <p>The limit is set per session here ({@code idle_session_timeout},
 * {@code wait_timeout}) because the test servers are shared; the connection
 * the pool opens up front is never borrowed, so the pool's reset on return
 * never gets the chance to undo it.
 */
@Timeout(120)
class IdleLimitTest {

    /** Seconds the server gives an idle session in these tests. */
    private static final int LIMIT = 4;

    record Db(String name, String url, String passwordFile, String setLimit, Duration expected) {

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
                        TestHosts.postgresPasswordFile(),
                        "set idle_session_timeout = '" + LIMIT + "s'",
                        Duration.ofSeconds(LIMIT)),
                new Db("MySQL", "jdbc:seclume:mysql://" + host + ":3307/seclume_test"
                        + "?user=seclume_test&tls=off&allowPublicKeyRetrieval=true",
                        ".local-mysql-password", "set session wait_timeout = " + LIMIT,
                        Duration.ofSeconds(LIMIT)),
                new Db("SQL Server", "jdbc:seclume:sqlserver://" + host
                        + ":1433/master?user=sa&trustServerCertificate=true",
                        ".local-mssql-password", null, null),
                new Db("Oracle", "jdbc:seclume:oracle://" + host + ":1521/FREEPDB1"
                        + "?user=seclume_test", ".local-oracle-password", null, null));
    }

    static List<Db> limited() {
        return databases().stream().filter(db -> db.setLimit() != null).toList();
    }

    @Test
    void theKeepaliveIsThreeQuartersOfTheLimit() {
        assertEquals(Duration.ofSeconds(45).toNanos(),
                SeclumePool.keepaliveBelow(Duration.ofMinutes(1)));
        assertEquals(Duration.ofSeconds(1).toNanos(),
                SeclumePool.keepaliveBelow(Duration.ofMillis(200)));
        assertEquals(0, SeclumePool.keepaliveBelow(null));
        assertEquals(0, SeclumePool.keepaliveBelow(Duration.ZERO));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void theDriverReadsTheServersLimit(Db db) throws Exception {
        try (Connection connection = open(url(db))) {
            ServerIdleLimit limit = connection.unwrap(ServerIdleLimit.class);
            if (db.setLimit() == null) {
                // SQL Server has none; the Oracle test user's profile is UNLIMITED.
                assertNull(limit.idleLimit(), db.name());
                return;
            }
            execute(connection, db.setLimit());
            assertEquals(db.expected(), limit.idleLimit());
        }
    }

    /**
     * The pool's connection outlives the limit twice over; the control - a
     * session with the same limit, left idle beside it without a pool - is
     * closed by the server in the same time.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("limited")
    void thePoolKeepsItsIdleConnectionAliveBelowTheLimit(Db db) throws Exception {
        Connection control = DriverManager.getConnection(url(db));
        execute(control, db.setLimit());
        PoolSettings settings = new PoolSettings();
        settings.setName("idle");
        settings.setMaximumPoolSize(1);
        settings.setMinimumIdle(1);
        settings.setValidationTimeout(Duration.ofMillis(500));   // housekeeping every 0.5 s
        try (SeclumePool pool = new SeclumePool(new LimitingSource(url(db), db.setLimit()),
                settings)) {
            pool.warmup();
            Thread.sleep((LIMIT * 2 + 1) * 1000L);
            try (Connection connection = pool.getConnection();
                 Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(db.name().equals("Oracle")
                         ? "select 1 from dual" : "select 1")) {
                assertTrue(rows.next());
            }
            PoolStatistics statistics = pool.statistics();
            assertEquals(1, statistics.created(),
                    "the idle connection was lost and replaced: " + statistics);
            assertEquals(0, statistics.retired(), statistics.toString());
        } finally {
            try (control) {
                assertFalse(control.isValid(2),
                        "the control: the server did not close an idle session");
            }
        }
    }

    /**
     * Oracle's listener refuses a burst of logins for a moment (ORA-12516,
     * transient) while the modules build side by side; asked again, it answers.
     */
    private static Connection open(String url) throws Exception {
        for (int attempt = 1; ; attempt++) {
            try {
                return DriverManager.getConnection(url);
            } catch (java.sql.SQLTransientConnectionException busy) {
                if (attempt == 5) {
                    throw busy;
                }
                Thread.sleep(500L * attempt);
            }
        }
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

    private static void execute(Connection c, String sql) throws SQLException {
        try (Statement s = c.createStatement()) {
            s.execute(sql);
        }
    }

    /** Opens a connection and gives its session the short idle limit. */
    private record LimitingSource(String url, String setLimit) implements DataSource {

        @Override
        public Connection getConnection() throws SQLException {
            Connection connection = DriverManager.getConnection(url);
            execute(connection, setLimit);
            return connection;
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
