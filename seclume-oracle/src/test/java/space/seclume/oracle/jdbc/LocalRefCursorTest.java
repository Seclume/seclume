package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
 * Procedures that hand back a {@code SYS_REFCURSOR}.
 *
 * <p>Oracle answers such a bind with neither a value nor rows: the slot holds
 * the <b>description</b> of the result the procedure opened and then the
 * number of the cursor it left standing, and the rows are fetched from that
 * cursor afterwards like the rows of any query. Two details in that had to be
 * measured against a real instance rather than reasoned about, and both fail
 * in a way that looks like something else:
 *
 * <ul>
 *   <li>the bind is described with a buffer size of <b>one</b>; with zero the
 *       server answers ORA-06502, a PL/SQL conversion error, which reads like
 *       a mistake in the procedure;</li>
 *   <li>the description inside the bind has no leading block, unlike the
 *       {@code DESCRIBE_INFO} message it otherwise is. Reading one as the
 *       other yields a plausible number of columns full of nonsense, with no
 *       error anywhere.</li>
 * </ul>
 *
 * <p>Hence these tests. They are the only thing standing between that shape
 * and a silent regression.
 */
class LocalRefCursorTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);
    private static final String USER =
            System.getProperty("seclume.oracle.user", "seclume_test");
    private static final String SERVICE =
            System.getProperty("seclume.oracle.service", "FREEPDB1");

    private static final List<String> PROCEDURES = List.of(
            "zl_cursor_rows", "zl_cursor_empty", "zl_cursor_and_number",
            "zl_cursor_many", "zl_cursor_wide");

    private static String url;

    @BeforeAll
    static void findTheServerAndCreateTheProcedures() throws Exception {
        Path password = null;
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
        url = "jdbc:seclume:oracle://" + HOST + ":" + PORT + "/" + SERVICE
                + "?user=" + USER + "&provider=file&path="
                + password.toString().replace('\\', '/');

        try (Connection connection = connect();
             Statement ddl = connection.createStatement()) {
            ddl.execute("""
                    create or replace procedure zl_cursor_rows(result out sys_refcursor) as
                    begin
                        open result for
                            select 1 as n, 'alpha' as t from dual
                            union all select 2, 'beta' from dual
                            order by n;
                    end;
                    """);
            ddl.execute("""
                    create or replace procedure zl_cursor_empty(result out sys_refcursor) as
                    begin
                        open result for select 1 as n from dual where 1 = 0;
                    end;
                    """);
            ddl.execute("""
                    create or replace procedure zl_cursor_and_number(
                        factor in number, result out sys_refcursor, total out number) as
                    begin
                        open result for
                            select 1 * factor as scaled from dual
                            union all select 2 * factor from dual
                            order by 1;
                        total := 3 * factor;
                    end;
                    """);
            ddl.execute("""
                    create or replace procedure zl_cursor_many(
                        first_result out sys_refcursor, second_result out sys_refcursor) as
                    begin
                        open first_result for select 'one' as which from dual;
                        open second_result for select 'two' as which from dual;
                    end;
                    """);
            // More rows than one fetch brings, so the loop that asks for the
            // rest is exercised instead of assumed.
            ddl.execute("""
                    create or replace procedure zl_cursor_wide(result out sys_refcursor) as
                    begin
                        open result for
                            select level as n, rpad('x', 40, 'x') as pad
                            from dual connect by level <= 500;
                    end;
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
            for (String name : PROCEDURES) {
                try {
                    ddl.execute("drop procedure " + name);
                } catch (SQLException gone) {
                    // Never created, or dropped already.
                }
            }
        }
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(url);
    }

    @Test
    void aProcedureCanHandBackACursor() throws Exception {
        try (Connection connection = connect();
             CallableStatement call = connection.prepareCall("{call zl_cursor_rows(?)}")) {
            call.registerOutParameter(1, Types.REF_CURSOR);
            call.execute();

            ResultSet rows = (ResultSet) call.getObject(1);
            assertNotNull(rows);
            assertEquals("N", rows.getMetaData().getColumnLabel(1));
            assertEquals("T", rows.getMetaData().getColumnLabel(2));
            assertTrue(rows.next());
            assertEquals(1, rows.getInt("N"));
            assertEquals("alpha", rows.getString("T"));
            assertTrue(rows.next());
            assertEquals(2, rows.getInt("N"));
            assertEquals("beta", rows.getString("T"));
            assertFalse(rows.next());
        }
    }

    /** An empty cursor is not the same as no cursor - and is not an error. */
    @Test
    void anEmptyCursorIsStillACursor() throws Exception {
        try (Connection connection = connect();
             CallableStatement call = connection.prepareCall("{call zl_cursor_empty(?)}")) {
            call.registerOutParameter(1, Types.REF_CURSOR);
            call.execute();

            ResultSet rows = (ResultSet) call.getObject(1);
            assertNotNull(rows, "the procedure opened a cursor; it has no rows");
            assertEquals("N", rows.getMetaData().getColumnLabel(1));
            assertFalse(rows.next());
        }
    }

    /**
     * A cursor and an ordinary output in the same call. This is the case that
     * catches an offset being one field wrong: the number after the cursor is
     * read from wherever the cursor's own fields ended.
     */
    @Test
    void aCursorAndANumberComeBackTogether() throws Exception {
        try (Connection connection = connect();
             CallableStatement call =
                     connection.prepareCall("{call zl_cursor_and_number(?, ?, ?)}")) {
            call.setInt(1, 5);
            call.registerOutParameter(2, Types.REF_CURSOR);
            call.registerOutParameter(3, Types.INTEGER);
            call.execute();

            List<Integer> scaled = new ArrayList<>();
            ResultSet rows = (ResultSet) call.getObject(2);
            while (rows.next()) {
                scaled.add(rows.getInt("SCALED"));
            }
            assertEquals(List.of(5, 10), scaled);
            assertEquals(15, call.getInt(3));
        }
    }

    /** Two cursors from one call, each with its own rows. */
    @Test
    void twoCursorsDoNotOverwriteEachOther() throws Exception {
        try (Connection connection = connect();
             CallableStatement call = connection.prepareCall("{call zl_cursor_many(?, ?)}")) {
            call.registerOutParameter(1, Types.REF_CURSOR);
            call.registerOutParameter(2, Types.REF_CURSOR);
            call.execute();

            ResultSet first = (ResultSet) call.getObject(1);
            ResultSet second = (ResultSet) call.getObject(2);

            assertTrue(first.next());
            assertEquals("one", first.getString("WHICH"));
            assertTrue(second.next());
            assertEquals("two", second.getString("WHICH"));

            // Read after the other one has been walked: the second cursor's
            // rows must not have landed in the first one's memory.
            assertFalse(first.next());
            assertFalse(second.next());
        }
    }

    /** More rows than one fetch brings, so the loop is proven and not assumed. */
    @Test
    void aCursorLongerThanOneFetchIsReadToTheEnd() throws Exception {
        try (Connection connection = connect();
             CallableStatement call = connection.prepareCall("{call zl_cursor_wide(?)}")) {
            call.registerOutParameter(1, Types.REF_CURSOR);
            call.execute();

            ResultSet rows = (ResultSet) call.getObject(1);
            int seen = 0;
            while (rows.next()) {
                seen++;
                assertEquals(seen, rows.getInt("N"));
                assertEquals(40, rows.getString("PAD").length());
            }
            assertEquals(500, seen);
        }
    }

    /** A cursor still works when the call is run twice on the same statement. */
    @Test
    void aSecondExecutionBringsItsOwnCursor() throws Exception {
        try (Connection connection = connect();
             CallableStatement call = connection.prepareCall("{call zl_cursor_rows(?)}")) {
            for (int round = 0; round < 3; round++) {
                call.registerOutParameter(1, Types.REF_CURSOR);
                call.execute();
                ResultSet rows = (ResultSet) call.getObject(1);
                assertTrue(rows.next(), "round " + round);
                assertEquals(1, rows.getInt("N"), "round " + round);
                assertTrue(rows.next());
                assertEquals(2, rows.getInt("N"));
                assertFalse(rows.next());
            }
        }
    }

    /** Asking for a cursor where the procedure has none is an error, not a null. */
    @Test
    void executeQueryPointsAtTheWayThatWorks() throws Exception {
        try (Connection connection = connect();
             CallableStatement call = connection.prepareCall("{call zl_cursor_rows(?)}")) {
            call.registerOutParameter(1, Types.REF_CURSOR);
            SQLException refusal = org.junit.jupiter.api.Assertions.assertThrows(
                    SQLException.class, call::executeQuery);
            assertTrue(refusal.getMessage().contains("REF_CURSOR"), refusal.getMessage());
        }
    }
}
