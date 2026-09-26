package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * A SQL Server result handed out while its rows are still arriving.
 *
 * <p>{@code executeQuery} returns after the first packet with rows, and
 * {@code next()} reads on - so the application works while the network does,
 * as with mssql-jdbc. The connection is one conversation, though: whatever
 * else uses it while such a result is open has to find the rest of it read off
 * the wire first, and the rows still there for the result that is open. That
 * is what these cases are about - each reads more rows than one packet holds.
 */
@Timeout(300)
class SqlServerPausedResultTest {

    private static final int ROWS = 20_000;
    private static final String MANY = "select top " + ROWS + " row_number() over (order by "
            + "(select 1)) n, replicate('x', 80) t from sys.all_objects a "
            + "cross join sys.all_objects b";

    private String url;

    @BeforeEach
    void server() {
        int port = Integer.getInteger("seclume.mssql.port", 1433);
        Path secret = TypeCatalogTest.locate(".local-mssql-password");
        String host = System.getProperty("seclume.mssql.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        url = "jdbc:seclume:sqlserver://" + host + ":" + port
                + "/master?user=sa&trustServerCertificate=true&provider=file&path="
                + TypeCatalogTest.slash(secret);
    }

    @Test
    void anotherStatementInTheMiddleLeavesEveryRowInPlace() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement first = connection.createStatement();
             ResultSet rows = first.executeQuery(MANY)) {
            long expected = 1;
            while (rows.next()) {
                assertEquals(expected, rows.getLong(1));
                if (expected == 10) {
                    // Another statement, a prepared one, metadata and a
                    // transaction - each has to find the connection free.
                    try (Statement other = connection.createStatement();
                         ResultSet one = other.executeQuery("select 42")) {
                        assertTrue(one.next());
                        assertEquals(42, one.getInt(1));
                    }
                    try (PreparedStatement prepared = connection.prepareStatement("select ?")) {
                        prepared.setInt(1, 7);
                        try (ResultSet seven = prepared.executeQuery()) {
                            assertTrue(seven.next());
                            assertEquals(7, seven.getInt(1));
                        }
                    }
                    connection.getMetaData().getTables(null, "sys", "objects", null).close();
                    connection.setAutoCommit(false);
                    connection.commit();
                    connection.setAutoCommit(true);
                }
                expected++;
            }
            assertEquals(ROWS + 1, expected);
        }
    }

    @Test
    void aResultClosedHalfWayLeavesTheConnectionReady() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            for (int round = 0; round < 3; round++) {
                try (ResultSet rows = statement.executeQuery(MANY)) {
                    for (int i = 0; i < 100; i++) {
                        assertTrue(rows.next());
                    }
                }
                // The same statement again, and another one.
                try (ResultSet rows = statement.executeQuery("select 1")) {
                    assertTrue(rows.next());
                    assertEquals(1, rows.getInt(1));
                    assertFalse(rows.next());
                }
            }
            try (Statement other = connection.createStatement()) {
                other.executeQuery(MANY).next();          // left open, never closed
            }
            try (ResultSet rows = statement.executeQuery("select 2")) {
                assertTrue(rows.next());
                assertEquals(2, rows.getInt(1));
            }
        }
    }

    @Test
    void aSecondResultBehindAPausedOneIsNotLost() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            assertTrue(statement.execute(MANY + "; select 'second' s"));
            try (ResultSet rows = statement.getResultSet()) {
                assertTrue(rows.next());
                assertEquals(1, rows.getLong(1));
            }
            assertTrue(statement.getMoreResults());
            try (ResultSet rows = statement.getResultSet()) {
                assertTrue(rows.next());
                assertEquals("second", rows.getString(1));
            }
            assertFalse(statement.getMoreResults());
        }
        // Read to the end, and then the second one.
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            assertTrue(statement.execute(MANY + "; select 'second' s"));
            int count = 0;
            try (ResultSet rows = statement.getResultSet()) {
                while (rows.next()) {
                    count++;
                }
            }
            assertEquals(ROWS, count);
            assertTrue(statement.getMoreResults());
            try (ResultSet rows = statement.getResultSet()) {
                assertTrue(rows.next());
                assertEquals("second", rows.getString(1));
            }
        }
    }

    @Test
    void anErrorAfterTheFirstRowsArrivesAtNext() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            List<Long> seen = new ArrayList<>();
            SQLException failure = assertThrows(SQLException.class, () -> {
                try (ResultSet rows = statement.executeQuery("select top " + ROWS
                        + " 1 / (" + (ROWS - 100) + " - row_number() over (order by "
                        + "(select 1))) + row_number() over (order by (select 1)) n, "
                        + "replicate('x', 80) t from sys.all_objects a "
                        + "cross join sys.all_objects b")) {
                    while (rows.next()) {
                        seen.add(rows.getLong(1));
                    }
                }
            });
            assertTrue(failure.getMessage().contains("zero"), failure.getMessage());
            assertTrue(seen.size() > 0, "the rows before the error were handed out");
            try (ResultSet rows = statement.executeQuery("select 3")) {
                assertTrue(rows.next());
                assertEquals(3, rows.getInt(1));
            }
        }
    }

    /**
     * Values of a megabyte and more, several in one row: they span dozens of
     * packets, the buffer has to grow while the row is incomplete, and the
     * bytes of the next packet already behind the message must survive that.
     * They did not - growing copied up to the message's end - and the first
     * large nvarchar(max) broke the connection with "a chunk of -67045888".
     */
    @Test
    void largeValuesAcrossManyPacketsReadWhole() throws Exception {
        String body = "Zeile mit Umlauten äöü\n".repeat(30_000);
        byte[] data = new byte[1_700_000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 31 + 7);
        }
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists ##seclume_plp; create table ##seclume_plp "
                    + "(id int, a nvarchar(max), b varbinary(max), n int, c nvarchar(max))");
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into ##seclume_plp values (?, ?, ?, 42, ?)")) {
                for (int id = 1; id <= 3; id++) {
                    insert.setInt(1, id);
                    insert.setString(2, body);
                    insert.setBytes(3, data);
                    insert.setString(4, "short " + id);
                    insert.executeUpdate();
                }
            }
            try (ResultSet rows = statement.executeQuery(
                    "select id, a, b, n, c from ##seclume_plp order by id")) {
                for (int id = 1; id <= 3; id++) {
                    assertTrue(rows.next());
                    assertEquals(id, rows.getInt(1));
                    assertEquals(body, rows.getString(2));
                    assertTrue(java.util.Arrays.equals(data, rows.getBytes(3)));
                    assertEquals(42, rows.getInt(4));
                    assertEquals("short " + id, rows.getString(5));
                }
                assertFalse(rows.next());
            }
        }
    }

    @Test
    void manyRowsReadLikeMssqlJdbc() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             PreparedStatement statement = connection.prepareStatement(
                     MANY.replace("top " + ROWS, "top (?)"))) {
            statement.setInt(1, ROWS);
            long sum = 0;
            int count = 0;
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    sum += rows.getLong(1);
                    assertEquals(80, rows.getString(2).length());
                    count++;
                }
            }
            assertEquals(ROWS, count);
            assertEquals((long) ROWS * (ROWS + 1) / 2, sum);
        }
    }
}
