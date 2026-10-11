package space.seclume.sqlserver.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * SQL Server's session recovery, against a real server: a connection killed
 * while it sat idle is replaced before the next statement, and the server
 * puts the session's state on the new one - database, language, SET options.
 *
 * <p>And the two cases where it must not happen: a session the server marked
 * unrecoverable (a temporary table), and one in a transaction. There the
 * statement fails as before, with the SQLState of a broken connection.
 *
 * <p>The connection is killed with {@code KILL} from a second one, which is
 * what a server restart or an Availability Group failover looks like from
 * the client: the session is gone and the socket is closed.
 */
@Timeout(120)
class LocalSessionRecoveryTest {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mssql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:sqlserver://" + HOST + ":" + PORT + "/master"
                + "?user=sa&trustServerCertificate=true&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    @Test
    void anIdleSessionKilledComesBackWithItsSettings() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Connection admin = DriverManager.getConnection(url)) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("SET DATEFORMAT dmy; SET LANGUAGE Deutsch; "
                        + "SET ANSI_WARNINGS OFF; USE tempdb");
            }
            TdsConnection tds = (TdsConnection) connection;
            assertTrue(tds.session().recoverable(), "the server should offer recovery");
            String killed = ask(connection, "select @@spid");

            kill(admin, killed);
            Thread.sleep(1_500);                         // idle long enough to be looked at

            assertEquals("tempdb", ask(connection, "select db_name()"));
            assertEquals(1, tds.session().recoveries(), "the session was put back once");
            assertEquals("Deutsch", ask(connection, "select @@language"));
            assertEquals("dmy", ask(connection, "select date_format from sys.dm_exec_sessions "
                    + "where session_id = @@spid"));
            assertEquals("0", ask(connection, "select cast(sessionproperty('ANSI_WARNINGS') "
                    + "as int)"));

            // And again: the state is kept for a second recovery as well.
            try (Statement statement = connection.createStatement()) {
                statement.execute("SET DATEFORMAT ymd");
            }
            kill(admin, ask(connection, "select @@spid"));
            Thread.sleep(1_500);
            assertEquals("ymd", ask(connection, "select date_format from sys.dm_exec_sessions "
                    + "where session_id = @@spid"));
            assertEquals(2, tds.session().recoveries());
            assertEquals("tempdb", ask(connection, "select db_name()"));
        }
    }

    @Test
    void aTemporaryTableMakesTheSessionUnrecoverable() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Connection admin = DriverManager.getConnection(url)) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("create table #mine (id int)");
            }
            TdsConnection tds = (TdsConnection) connection;
            assertFalse(tds.session().recoverable(),
                    "a temporary table cannot be put back, and the server says so");
            kill(admin, ask(connection, "select @@spid"));
            Thread.sleep(1_500);
            SQLException told = assertThrows(SQLException.class,
                    () -> ask(connection, "select count(*) from #mine"));
            assertTrue(told.getSQLState().startsWith("08"), told.getSQLState());
            assertTrue(connection.isClosed(), "the connection is gone, not put back");
        }
    }

    @Test
    void aTransactionIsNeverCarriedOver() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Connection admin = DriverManager.getConnection(url)) {
            // An explicit one: under setAutoCommit(false) a SELECT without a
            // table does not open one, and recovering there would be right.
            try (Statement statement = connection.createStatement()) {
                statement.execute("BEGIN TRANSACTION");
            }
            assertEquals("1", ask(connection, "select @@trancount"));
            kill(admin, ask(connection, "select @@spid"));
            Thread.sleep(1_500);
            SQLException told = assertThrows(SQLException.class,
                    () -> ask(connection, "select 1"));
            assertTrue(told.getSQLState().startsWith("08"), told.getSQLState());
            assertTrue(connection.isClosed(), "the connection is gone, not put back");
        }
    }

    private static void kill(Connection admin, String spid) throws SQLException {
        try (Statement statement = admin.createStatement()) {
            statement.execute("KILL " + Integer.parseInt(spid.trim()));
        }
    }

    private static String ask(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }
}
