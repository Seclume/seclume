package space.seclume.oracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.SessionReset;
import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.secret.SecretProviders;

/**
 * Logging off and in again on the same connection gives a session with
 * nothing of the one before - the reset Oracle itself does not have.
 *
 * <p>Each kind of state a session can carry is set, and each is checked to
 * be at its default after {@link OracleSession#logInAgain}: the client
 * identifier, an application context, a package variable, NLS settings, the
 * current schema, the enabled roles, rows of a temporary table - and an
 * uncommitted row, which a logoff would have committed.
 */
@Timeout(120)
class LocalLogInAgainTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);
    private static final String SERVICE = System.getProperty("seclume.oracle.service", "FREEPDB1");

    private static Path password;

    @BeforeAll
    static void findTheServer() throws Exception {
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle listener on " + HOST + ":" + PORT);
        }
        try (OracleSession setup = open()) {
            run(setup, "begin execute immediate 'create global temporary table zl_again_gtt "
                    + "(n number) on commit preserve rows'; exception when others then null; end;");
            run(setup, "begin execute immediate 'create table zl_again_rows (n number)'; "
                    + "exception when others then null; end;");
            run(setup, "create or replace package zl_again_pkg as n number := 0; "
                    + "function get_n return number; procedure set_ctx(v varchar2); end;");
            run(setup, "create or replace package body zl_again_pkg as "
                    + "function get_n return number is begin return n; end; "
                    + "procedure set_ctx(v varchar2) is begin "
                    + "dbms_session.set_context('zl_again_ctx', 'k', v); end; end;");
            try {
                run(setup, "create or replace context zl_again_ctx using zl_again_pkg");
            } catch (java.sql.SQLException e) {
                Assumptions.abort("seclume_test may not create a context "
                        + "(grant create any context): " + e.getMessage());
            }
        }
    }

    /**
     * Runs a statement and fails on a server error. OracleSession.query hands
     * an error back as its result rather than throwing - the JDBC layer reads
     * it - so a setup step that failed went unnoticed: on a server where the
     * user may not create a context, the context was never set and the test
     * said only that its state was missing.
     */
    private static void run(OracleSession session, String sql) throws java.sql.SQLException {
        space.seclume.oracle.net.TtcResult result = session.query(sql, row -> { });
        if (result.isFailure()) {
            throw new java.sql.SQLException(result.errorText(), "HY000", result.errorNumber());
        }
    }

    private static OracleSession.Settings settings() {
        return new OracleSession.Settings(HOST, PORT, SERVICE, "seclume_test",
                SecretProviders.of(Map.of("provider", "file", "path", password.toString())),
                5_000, HostList.of(HOST, PORT), ResultLimit.NONE, TlsMode.OFF);
    }

    private static OracleSession open() throws Exception {
        return OracleSession.open(settings());
    }

    /** What each kind of session state reads, in one line of text. */
    private static String state(OracleSession session) throws Exception {
        return String.join(" | ",
                session.askOneValue("select nvl(sys_context('userenv','client_identifier'),'-') "
                        + "from dual"),
                session.askOneValue("select nvl(sys_context('zl_again_ctx','k'),'-') from dual"),
                session.askOneValue("select to_char(seclume_test.zl_again_pkg.get_n) from dual"),
                session.askOneValue("select value from nls_session_parameters "
                        + "where parameter = 'NLS_DATE_FORMAT'"),
                session.askOneValue("select sys_context('userenv','current_schema') from dual"),
                session.askOneValue("select to_char(count(*)) from session_roles"),
                session.askOneValue("select to_char(count(*)) from seclume_test.zl_again_gtt"));
    }

    @Test
    void theNewSessionCarriesNothingOfTheOld() throws Exception {
        try (OracleSession session = open()) {
            String fresh = state(session);
            String before = session.askOneValue(
                    "select sys_context('userenv','sessionid') from dual");

            run(session, "begin dbms_session.set_identifier('tenant-A'); end;");
            run(session, "begin seclume_test.zl_again_pkg.set_ctx('tenant-A'); end;");
            run(session, "begin seclume_test.zl_again_pkg.n := 42; end;");
            run(session, "insert into seclume_test.zl_again_gtt values (1)");
            run(session, "alter session set nls_date_format = 'YYYY'");
            run(session, "set role none");
            run(session, "alter session set current_schema = sys");
            assertEquals("tenant-A | tenant-A | 42 | YYYY | SYS | 0 | 1", state(session),
                    "the state was not set - the test would prove nothing");

            session.logInAgain();

            assertEquals(fresh, state(session), "the new session inherited state");
            assertNotEquals(before, session.askOneValue(
                    "select sys_context('userenv','sessionid') from dual"),
                    "no new session was made");
        }
    }

    @Test
    void anOpenTransactionIsRolledBackNotCommitted() throws Exception {
        try (OracleSession session = open()) {
            run(session, "delete from zl_again_rows");
            session.setAutoCommit(false);
            run(session, "insert into zl_again_rows values (7)");
            session.logInAgain();
            assertEquals("0", session.askOneValue("select to_char(count(*)) from zl_again_rows"),
                    "the logoff committed the open transaction");
        }
    }

    /** Parsed statements belonged to the old session; the new one parses them again. */
    @Test
    void statementsRunAsBeforeAfterwards() throws Exception {
        try (OracleSession session = open()) {
            for (int round = 0; round < 3; round++) {
                for (int i = 0; i < 5; i++) {
                    assertEquals(Integer.toString(i), session.askOneValue(
                            "select to_char(" + i + ") from dual"));
                }
                session.logInAgain();
            }
        }
    }

    /**
     * Through JDBC, the way the pool uses it: the reset is owed at the return,
     * made when settled, and the connection keeps its isolation level.
     */
    @Test
    void thePoolsResetIsALoginOnTheSameConnection() throws Exception {
        String url = "jdbc:seclume:oracle://" + HOST + ":" + PORT + "/" + SERVICE
                + "?user=seclume_test&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/');
        try (Connection c = java.sql.DriverManager.getConnection(url)) {
            SessionReset reset = c.unwrap(SessionReset.class);
            String before = ask(c, "select sys_context('userenv','sessionid') from dual");
            c.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            try (Statement s = c.createStatement()) {
                s.execute("begin dbms_session.set_identifier('tenant-A'); end;");
            }

            assertTrue(reset.resetSessionState(), "Oracle still retires the session");
            assertTrue(reset.resetOwed(), "the login was made on the returning thread");
            reset.settleReset();
            assertFalse(reset.resetOwed());

            assertNotEquals(before, ask(c, "select sys_context('userenv','sessionid') from dual"));
            assertEquals("-", ask(c, "select nvl(sys_context('userenv','client_identifier'),'-') "
                    + "from dual"));
            assertEquals(Connection.TRANSACTION_SERIALIZABLE, c.getTransactionIsolation());
            // Owed and not settled: the next statement settles it first.
            String second = ask(c, "select sys_context('userenv','sessionid') from dual");
            assertTrue(reset.resetSessionState());
            assertNotEquals(second, ask(c, "select sys_context('userenv','sessionid') from dual"),
                    "a statement ran on the session that was to be replaced");
            assertFalse(reset.resetOwed());
        }
    }

    private static String ask(Connection c, String sql) throws Exception {
        try (Statement s = c.createStatement(); ResultSet rows = s.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }
}
