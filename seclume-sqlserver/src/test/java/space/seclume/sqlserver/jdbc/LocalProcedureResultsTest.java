package space.seclume.sqlserver.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Procedures that return rows, which on SQL Server means procedures that
 * select.
 *
 * <p>There is no cursor parameter here - that is Oracle's answer to the same
 * question. A T-SQL procedure simply selects, and the rows arrive as results
 * of the batch that called it, one after another in the token stream. So what
 * has to work is the part of JDBC nobody uses until they call a procedure:
 * {@code execute} saying whether there is a result, {@code getResultSet}
 * handing over the first, and {@code getMoreResults} walking to the next.
 *
 * <p>The awkward case is a procedure that both selects <b>and</b> has output
 * parameters, because the driver appends a select of its own to read those
 * back. That one is the last result of the answer and must not appear as a
 * third table the application never asked for.
 */
class LocalProcedureResultsTest {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);
    private static final String USER = "sa";

    private static String url;

    @BeforeAll
    static void findTheServerAndCreateTheProcedures() throws Exception {
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
                + "?user=" + USER + "&trustServerCertificate=true&provider=file&path="
                + password.toString().replace('\\', '/');

        try (Connection connection = connect();
             Statement ddl = connection.createStatement()) {
            ddl.execute("""
                    create or alter procedure zl_one_result as
                    begin
                        set nocount on;
                        select 1 as id, 'alpha' as name
                        union all select 2, 'beta'
                        order by id;
                    end
                    """);
            ddl.execute("""
                    create or alter procedure zl_two_results as
                    begin
                        set nocount on;
                        select 'first' as which;
                        select 10 as n union all select 20;
                    end
                    """);
            ddl.execute("""
                    create or alter procedure zl_rows_and_output
                        @factor int, @total int output as
                    begin
                        set nocount on;
                        select 1 * @factor as scaled union all select 2 * @factor;
                        set @total = 3 * @factor;
                    end
                    """);
            ddl.execute("""
                    create or alter procedure zl_no_rows @n int output as
                    begin
                        set nocount on;
                        set @n = 99;
                    end
                    """);
            ddl.execute("""
                    create or alter procedure zl_empty_result as
                    begin
                        set nocount on;
                        select 1 as id where 1 = 0;
                    end
                    """);
        }
    }

    @AfterAll
    static void dropTheProcedures() throws Exception {
        if (url == null) {
            return;
        }
        try (Connection connection = connect();
             Statement ddl = connection.createStatement()) {
            for (String name : List.of("zl_one_result", "zl_two_results", "zl_rows_and_output",
                    "zl_no_rows", "zl_empty_result")) {
                ddl.execute("drop procedure if exists " + name);
            }
        }
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(url);
    }

    @Test
    void aProcedureThatSelectsHandsTheRowsOver() throws Exception {
        try (Connection connection = connect();
             CallableStatement call = connection.prepareCall("{call zl_one_result}")) {
            assertTrue(call.execute(), "the procedure selects, so there is a result");
            try (ResultSet rows = call.getResultSet()) {
                assertNotNull(rows);
                assertTrue(rows.next());
                assertEquals(1, rows.getInt("id"));
                assertEquals("alpha", rows.getString("name"));
                assertTrue(rows.next());
                assertEquals("beta", rows.getString("name"));
                assertFalse(rows.next());
            }
            assertFalse(call.getMoreResults(), "there was only one result");
        }
    }

    /** The same thing through executeQuery, which is how most callers write it. */
    @Test
    void executeQueryWorksOnAProcedureThatSelects() throws Exception {
        try (Connection connection = connect();
             CallableStatement call = connection.prepareCall("{call zl_one_result}");
             ResultSet rows = call.executeQuery()) {
            assertTrue(rows.next());
            assertEquals(1, rows.getInt(1));
        }
    }

    /**
     * Two selects are two results, not one long one. This is the case that
     * used to come back merged, because a row carries its own columns and
     * nothing marked where one result ended.
     */
    @Test
    void twoSelectsAreTwoResults() throws Exception {
        try (Connection connection = connect();
             CallableStatement call = connection.prepareCall("{call zl_two_results}")) {
            assertTrue(call.execute());

            ResultSet first = call.getResultSet();
            assertTrue(first.next());
            assertEquals("first", first.getString("which"));
            assertFalse(first.next());

            assertTrue(call.getMoreResults(), "a second result followed");
            ResultSet second = call.getResultSet();
            List<Integer> numbers = new ArrayList<>();
            while (second.next()) {
                numbers.add(second.getInt("n"));
            }
            assertEquals(List.of(10, 20), numbers);

            assertFalse(call.getMoreResults());
        }
    }

    /**
     * Rows and an output parameter together. The driver appends its own
     * select to read the output back, and that one must not show up as a
     * second table.
     */
    @Test
    void rowsAndAnOutputParameterDoNotGetInEachOthersWay() throws Exception {
        try (Connection connection = connect();
             CallableStatement call = connection.prepareCall("{call zl_rows_and_output(?, ?)}")) {
            call.setInt(1, 5);
            call.registerOutParameter(2, Types.INTEGER);
            assertTrue(call.execute());

            List<Integer> scaled = new ArrayList<>();
            try (ResultSet rows = call.getResultSet()) {
                while (rows.next()) {
                    scaled.add(rows.getInt("scaled"));
                }
            }
            assertEquals(List.of(5, 10), scaled);
            assertFalse(call.getMoreResults(),
                    "the output row is the driver's own and is not a result of the call");

            assertEquals(15, call.getInt(2));
        }
    }

    /** A procedure with only an output parameter still has no result set. */
    @Test
    void aProcedureWithoutRowsReportsNoResult() throws Exception {
        try (Connection connection = connect();
             CallableStatement call = connection.prepareCall("{call zl_no_rows(?)}")) {
            call.registerOutParameter(1, Types.INTEGER);
            assertFalse(call.execute(), "nothing was selected");
            assertEquals(null, call.getResultSet());
            assertEquals(99, call.getInt(1));
        }
    }

    /**
     * A select that matched nothing is an empty result, not the absence of
     * one - and an application branches on the difference.
     */
    @Test
    void anEmptyResultIsStillAResult() throws Exception {
        try (Connection connection = connect();
             CallableStatement call = connection.prepareCall("{call zl_empty_result}")) {
            assertTrue(call.execute(), "there is a result; it has no rows");
            try (ResultSet rows = call.getResultSet()) {
                assertNotNull(rows);
                assertFalse(rows.next());
                assertEquals("id", rows.getMetaData().getColumnLabel(1));
            }
        }
    }

    /** The same walk over a plain batch, which is where the boundary really lives. */
    @Test
    void aBatchOfTwoSelectsIsAlsoTwoResults() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            assertTrue(statement.execute("select 'a' as x; select 'b' as y"));
            assertEquals("x", statement.getResultSet().getMetaData().getColumnLabel(1));
            assertTrue(statement.getResultSet().next());
            assertEquals("a", statement.getResultSet().getString(1));

            assertTrue(statement.getMoreResults());
            assertEquals("y", statement.getResultSet().getMetaData().getColumnLabel(1));
            assertTrue(statement.getResultSet().next());
            assertEquals("b", statement.getResultSet().getString(1));

            assertFalse(statement.getMoreResults());
        }
    }
}
