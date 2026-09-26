package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
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

import space.seclume.tck.TestHosts;

/**
 * The tenant leak: a borrower sets session state with a statement - the way
 * row-level security is usually wired, {@code SET app.tenant_id} - and
 * returns the connection. The next borrower of the same connection must not
 * see it. One connection in the pool, so the second borrow is the same
 * session, on all four.
 */
@Timeout(120)
class SessionResetTest {

    /** One database: how to set a "tenant", and how to read it back. */
    record Db(String name, String url, String passwordFile, String identity, String set,
              String read, String unset) {

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
                        TestHosts.postgresPasswordFile(), "select pg_backend_pid()",
                        "set app.tenant_id = '42'",
                        "select current_setting('app.tenant_id', true)", null),
                new Db("MySQL", "jdbc:seclume:mysql://" + host + ":3307/seclume_test"
                        + "?user=seclume_test&tls=off&allowPublicKeyRetrieval=true",
                        ".local-mysql-password", "select connection_id()",
                        "set @tenant_id = '42'", "select @tenant_id", null),
                new Db("SQL Server", "jdbc:seclume:sqlserver://" + host
                        + ":1433/master?user=sa&trustServerCertificate=true",
                        ".local-mssql-password", "select @@spid",
                        "exec sp_set_session_context 'tenant_id', '42'",
                        "select cast(session_context(N'tenant_id') as varchar(10))", null),
                new Db("Oracle", "jdbc:seclume:oracle://" + host + ":1521/FREEPDB1"
                        + "?user=seclume_test", ".local-oracle-password",
                        "select sys_context('USERENV', 'SID') from dual",
                        "begin dbms_session.set_identifier('42'); end;",
                        "select sys_context('USERENV', 'CLIENT_IDENTIFIER') from dual", null));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void theNextBorrowerDoesNotInheritTheTenant(Db db) throws Exception {
        try (SeclumePool pool = new SeclumePool(new UrlSource(url(db)), settings())) {
            String session;
            try (Connection c = pool.getConnection()) {
                session = ask(c, db.identity());
                assertEquals(null, blank(ask(c, db.read())), "a tenant before anyone set one");
                // A prepared statement the pool caches, to show it survives the reset.
                try (PreparedStatement p = c.prepareStatement(db.identity())) {
                    p.executeQuery().close();
                }
                execute(c, db.set());
                assertEquals("42", ask(c, db.read()));
            }
            try (Connection c = pool.getConnection()) {
                assertEquals(session, ask(c, db.identity()),
                        "not the same session - the test shows nothing");
                assertEquals(null, blank(ask(c, db.read())),
                        "the next borrower inherited the tenant");
                try (PreparedStatement p = c.prepareStatement(db.identity())) {
                    try (ResultSet rows = p.executeQuery()) {
                        assertTrue(rows.next(), "the cached statement broke with the reset");
                    }
                }
            }
        }
    }

    /**
     * A connection that set nothing goes back the ordinary way - the same
     * session, the isolation the pool had, nothing reset.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void aConnectionThatSetNothingGoesBackAsItWas(Db db) throws Exception {
        try (SeclumePool pool = new SeclumePool(new UrlSource(url(db)), settings())) {
            String session;
            try (Connection c = pool.getConnection()) {
                session = ask(c, db.identity());
                c.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
                ask(c, db.identity());
            }
            try (Connection c = pool.getConnection()) {
                assertEquals(session, ask(c, db.identity()));
                assertEquals(Connection.TRANSACTION_READ_COMMITTED == pooledDefault(db)
                                ? Connection.TRANSACTION_READ_COMMITTED
                                : pooledDefault(db), c.getTransactionIsolation(),
                        "the isolation was not put back");
            }
        }
    }

    /**
     * A statement the borrower left open is closed on return and counted; a
     * cached prepared statement closed the ordinary way is not a leak.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void statementsLeftOpenAreClosedOnReturnAndCounted(Db db) throws Exception {
        PoolSettings settings = settings();
        settings.setLeakDetectionThreshold(Duration.ofMinutes(5));
        try (SeclumePool pool = new SeclumePool(new UrlSource(url(db)), settings)) {
            Statement forgotten;
            try (Connection c = pool.getConnection()) {
                try (PreparedStatement cached = c.prepareStatement(db.identity())) {
                    cached.executeQuery().close();
                }
                forgotten = c.createStatement();
                forgotten.executeQuery(db.identity());           // and never closed
            }
            assertEquals(1, pool.statementLeaks(), "the forgotten statement was not noticed");
            assertTrue(forgotten.isClosed(), "the forgotten statement is still open");
            try (Connection c = pool.getConnection()) {
                try (PreparedStatement cached = c.prepareStatement(db.identity())) {
                    try (ResultSet rows = cached.executeQuery()) {
                        assertTrue(rows.next(), "the cached statement was closed as a leak");
                    }
                }
            }
            assertEquals(1, pool.statementLeaks(), "a cached statement was counted as a leak");
        }
    }

    /** Oracle cannot undo an ALTER SESSION: that connection is not lent again. */
    @Test
    void anAlteredOracleSessionIsReplacedNotLent() throws Exception {
        Db db = databases().get(3);
        try (SeclumePool pool = new SeclumePool(new UrlSource(url(db)), settings())) {
            // Not the SID: Oracle hands a freed one to the next session at once.
            String unique = "select sys_context('USERENV', 'SESSIONID') from dual";
            String session;
            try (Connection c = pool.getConnection()) {
                session = ask(c, unique);
                execute(c, "alter session set nls_date_format = 'YYYY'");
            }
            try (Connection c = pool.getConnection()) {
                assertNotEquals(session, ask(c, unique),
                        "the altered session was lent again");
                assertNotEquals("2026", ask(c, "select to_char(sysdate) from dual"));
            }
        }
    }

    private static int pooledDefault(Db db) {
        return db.name().equals("MySQL") ? Connection.TRANSACTION_REPEATABLE_READ
                : Connection.TRANSACTION_READ_COMMITTED;
    }

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setName("reset");
        settings.setMaximumPoolSize(1);
        settings.setConnectionTimeout(Duration.ofSeconds(10));
        return settings;
    }

    static String url(Db db) {
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

    private static String blank(String value) {
        return value == null || value.isEmpty() ? null : value;
    }

    private static String ask(Connection c, String sql) throws SQLException {
        try (Statement s = c.createStatement(); ResultSet rows = s.executeQuery(sql)) {
            return rows.next() ? rows.getString(1) : null;
        }
    }

    private static void execute(Connection c, String sql) throws SQLException {
        try (Statement s = c.createStatement()) {
            s.execute(sql);
        }
    }

    /** A pool wants a {@code DataSource}; a driver wants a URL. */
    record UrlSource(String url) implements DataSource {

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
