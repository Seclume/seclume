package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
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

import space.seclume.tck.TestHosts;

/**
 * A plain statement whose text holds several statements: one result each, in
 * order, through {@code getMoreResults} - what pgjdbc does and what R2DBC's
 * test kit asks for.
 *
 * <p>Before, the rows of every statement went into one result under the first
 * one's description: {@code select 1; select 'a', 'b'} came back as a single
 * result whose second row was read with the wrong columns.
 */
class MultipleResultsTest {

    private static String url;

    @BeforeAll
    static void server() {
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no PostgreSQL password file");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no PostgreSQL on " + host + ":" + port);
        }
        url = "jdbc:seclume:postgresql://" + host + ":" + port + "/seclume_test"
                + "?user=seclume_test&tls=off&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/');
    }

    @Test
    void eachStatementHasItsOwnResult() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            assertTrue(statement.execute(
                    "select 1 as n; select 'a' as x, 'b' as y union all select 'c', null; select 42"));
            try (ResultSet first = statement.getResultSet()) {
                assertEquals(1, first.getMetaData().getColumnCount());
                assertTrue(first.next());
                assertEquals(1, first.getInt(1));
                assertFalse(first.next(), "the rows of the next statement in this one");
            }
            assertTrue(statement.getMoreResults());
            try (ResultSet second = statement.getResultSet()) {
                assertEquals(2, second.getMetaData().getColumnCount());
                assertEquals("x", second.getMetaData().getColumnName(1));
                assertTrue(second.next());
                assertEquals("a", second.getString(1));
                assertEquals("b", second.getString(2));
                assertTrue(second.next());
                assertEquals("c", second.getString("x"));
                assertNull(second.getString("y"));
                assertFalse(second.next());
            }
            assertTrue(statement.getMoreResults());
            try (ResultSet third = statement.getResultSet()) {
                assertTrue(third.next());
                assertEquals(42, third.getInt(1));
            }
            assertFalse(statement.getMoreResults());
            assertEquals(-1, statement.getUpdateCount(), "the end is not an update count");
        }
    }

    @Test
    void updateCountsAndRowsTakeTurns() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            statement.execute("create temporary table zl_multi (n int)");
            assertFalse(statement.execute("insert into zl_multi values (1), (2); "
                    + "select n from zl_multi order by n; update zl_multi set n = n + 10; "
                    + "select sum(n) from zl_multi"));
            assertEquals(2, statement.getUpdateCount());
            assertTrue(statement.getMoreResults());
            ResultSet rows = statement.getResultSet();
            assertTrue(rows.next());
            assertEquals(1, rows.getInt(1));
            assertTrue(rows.next());
            assertEquals(2, rows.getInt(1));
            assertFalse(statement.getMoreResults());
            assertTrue(rows.isClosed(), "the result before stays open after moving on");
            assertEquals(2, statement.getUpdateCount());
            assertTrue(statement.getMoreResults());
            try (ResultSet sum = statement.getResultSet()) {
                assertTrue(sum.next());
                assertEquals(23, sum.getInt(1));
            }
            assertFalse(statement.getMoreResults());
            assertEquals(-1, statement.getUpdateCount());
        }
    }

    /** Running the statement again, or closing it, lets go of what was not read. */
    @Test
    void unreadResultsAreDroppedByTheNextExecution() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            for (int i = 0; i < 200; i++) {
                statement.execute("select " + i + "; select repeat('x', 5000); select 2");
            }
            try (ResultSet one = statement.executeQuery("select 7")) {
                assertTrue(one.next());
                assertEquals(7, one.getInt(1));
            }
            assertFalse(statement.getMoreResults(), "a result of an earlier execution");
            statement.execute("select 1; select 2");
        }
    }

    /** A statement of the text that fails fails the execution, as with pgjdbc. */
    @Test
    void aFailureLaterInTheTextIsTheExecutionsFailure() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            assertThrows(SQLException.class,
                    () -> statement.execute("select 1; select 1 / 0; select 3"));
            assertFalse(statement.getMoreResults());
            try (ResultSet after = statement.executeQuery("select 5")) {
                assertTrue(after.next());
                assertEquals(5, after.getInt(1));
            }
        }
    }

    /** One statement, as ever: one result and nothing more. */
    @Test
    void aSingleStatementHasOneResult() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            assertTrue(statement.execute("select 1"));
            assertFalse(statement.getMoreResults());
            assertEquals(-1, statement.getUpdateCount());
        }
    }
}
