package space.seclume.sqlserver.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * {@code Statement.execute} on a batch hands out every result in the order the
 * server sent it - update counts included, as JDBC and mssql-jdbc do. Before,
 * a count between two selects was not a result of its own: the selects came
 * back, the insert between them did not.
 *
 * <p>A prepared statement's and a procedure call's {@code execute()} the
 * same. And nothing else moves: executeQuery still takes the rows,
 * executeUpdate the count, and a procedure that inserts before it selects
 * still answers a callable statement's executeQuery with its select.
 */
@Timeout(120)
class LocalResultsInOrderTest {

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

    private static final String BATCH = "create table #zl_order (n int); "
            + "insert into #zl_order values (1), (2); "
            + "select n from #zl_order order by n; "
            + "update #zl_order set n = n + 10; "
            + "select sum(n) from #zl_order";

    @Test
    void countsAndRowsComeInTheOrderTheyWereSent() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            assertFalse(statement.execute(BATCH), "the insert's count comes first");
            assertEquals(2, statement.getUpdateCount());
            assertTrue(statement.getMoreResults());
            try (ResultSet rows = statement.getResultSet()) {
                assertTrue(rows.next());
                assertEquals(1, rows.getInt(1));
                assertTrue(rows.next());
                assertEquals(2, rows.getInt(1));
                assertFalse(rows.next());
            }
            assertFalse(statement.getMoreResults());
            assertEquals(2, statement.getUpdateCount(), "the update's count");
            assertTrue(statement.getMoreResults());
            try (ResultSet sum = statement.getResultSet()) {
                assertTrue(sum.next());
                assertEquals(23, sum.getInt(1));
            }
            assertFalse(statement.getMoreResults());
            assertEquals(-1, statement.getUpdateCount(), "the end is not a count");
        }
    }

    @Test
    void selectsAloneAreAsBefore() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            assertTrue(statement.execute("select 1; select 'x', 'y'"));
            try (ResultSet one = statement.getResultSet()) {
                assertTrue(one.next());
                assertEquals(1, one.getInt(1));
            }
            assertTrue(statement.getMoreResults());
            try (ResultSet two = statement.getResultSet()) {
                assertTrue(two.next());
                assertEquals("y", two.getString(2));
            }
            assertFalse(statement.getMoreResults());
            assertEquals(-1, statement.getUpdateCount());
        }
    }

    /** NOCOUNT means no counts - nothing is invented. */
    @Test
    void noCountMeansNoCounts() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            assertTrue(statement.execute("set nocount on; " + BATCH + "; set nocount off"));
            try (ResultSet rows = statement.getResultSet()) {
                assertTrue(rows.next());
            }
            assertTrue(statement.getMoreResults());
            assertFalse(statement.getMoreResults());
            assertEquals(-1, statement.getUpdateCount());
        }
    }

    @Test
    void executeQueryAndExecuteUpdateReadAsBefore() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            try (ResultSet rows = statement.executeQuery(BATCH)) {
                assertTrue(rows.next(), "executeQuery takes the first rows");
                assertEquals(1, rows.getInt(1));
            }
            statement.execute("create table #zl_twice (n int)");
            assertTrue(statement.executeUpdate(
                    "insert into #zl_twice values (1); insert into #zl_twice values (2), (3)") > 0);
        }
    }

    @Test
    void aPreparedStatementsExecuteIsInOrderToo() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("create table #zl_prep (n int)");
            try (java.sql.PreparedStatement prepared = connection.prepareStatement(
                    "insert into #zl_prep values (?), (?); select n from #zl_prep order by n")) {
                prepared.setInt(1, 4);
                prepared.setInt(2, 5);
                assertFalse(prepared.execute(), "the insert's count comes first");
                assertEquals(2, prepared.getUpdateCount());
                assertTrue(prepared.getMoreResults());
                try (ResultSet rows = prepared.getResultSet()) {
                    assertTrue(rows.next());
                    assertEquals(4, rows.getInt(1));
                }
                assertFalse(prepared.getMoreResults());
                assertEquals(-1, prepared.getUpdateCount());
            }
        }
    }

    /**
     * A procedure's {@code execute()}: what it counted, then what it selected,
     * then the next count - the output parameter read apart, as before.
     */
    @Test
    void aProcedureCallsExecuteIsInOrder() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("create table #zl_call (n int)");
            statement.execute("create or alter procedure zl_count_select_count @total int output "
                    + "as begin insert into #zl_call values (1), (2), (3); "
                    + "select n from #zl_call order by n; "
                    + "delete from #zl_call where n > 1; "
                    + "select @total = count(*) from #zl_call; end");
            try (CallableStatement call = connection.prepareCall(
                    "{call zl_count_select_count(?)}")) {
                call.registerOutParameter(1, java.sql.Types.INTEGER);
                assertFalse(call.execute(), "the insert's count comes first");
                assertEquals(3, call.getUpdateCount());
                assertTrue(call.getMoreResults());
                try (ResultSet rows = call.getResultSet()) {
                    assertTrue(rows.next());
                    assertEquals(1, rows.getInt(1));
                }
                assertFalse(call.getMoreResults());
                assertEquals(2, call.getUpdateCount(), "the delete's count");
                assertFalse(call.getMoreResults());
                assertEquals(1, call.getInt(1), "the output parameter");
            } finally {
                statement.execute("drop procedure zl_count_select_count");
            }
        }
    }

    /** A procedure that inserts before it selects answers a callable statement with its rows. */
    @Test
    void aProcedureCallIsAsBefore() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("create table #zl_proc (n int)");
            statement.execute("create or alter procedure zl_insert_then_select as begin "
                    + "insert into #zl_proc values (7); select n from #zl_proc; end");
            try (CallableStatement call = connection.prepareCall("{call zl_insert_then_select}");
                 ResultSet rows = call.executeQuery()) {
                assertTrue(rows.next());
                assertEquals(7, rows.getInt(1));
            } finally {
                statement.execute("drop procedure zl_insert_then_select");
            }
        }
    }
}
