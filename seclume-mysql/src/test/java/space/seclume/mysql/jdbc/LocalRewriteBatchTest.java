package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
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
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/** {@code rewriteBatchedInserts=true} against a real MySQL. */
@Timeout(120)
class LocalRewriteBatchTest {

    private static String url;
    private Connection connection;
    private String table;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mysql-password"),
                Path.of("..", ".local-mysql-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mysql-password");
        String host = TestHosts.database();
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, 3307), 2000);
        } catch (IOException e) {
            Assumptions.abort("no MySQL on " + host);
        }
        url = "jdbc:seclume:mysql://" + host + ":3307/seclume_test?user=seclume_test&tls=off"
                + "&allowPublicKeyRetrieval=true&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/');
    }

    @BeforeEach
    void table() throws SQLException {
        connection = DriverManager.getConnection(url + "&rewriteBatchedInserts=true");
        table = "rewrite_" + UUID.randomUUID().toString().substring(0, 8);
        execute("create table " + table + " (id int primary key, label varchar(60), "
                + "amount decimal(10,2))");
    }

    @AfterEach
    void drop() throws SQLException {
        try {
            execute("drop table " + table);
        } finally {
            connection.close();
        }
    }

    /** 300 rows: two blocks of 128, then 32, 8 and 4 - every shape, every row, in order. */
    @Test
    void anOddBatchArrivesWholeAndInOrder() throws Exception {
        long[] counts;
        try (PreparedStatement insert = connection.prepareStatement(
                "insert into " + table + " (id, label, amount) values (?, ?, ?)")) {
            for (int i = 0; i < 300; i++) {
                insert.setInt(1, i);
                insert.setString(2, i % 7 == 0 ? null : "row '" + i + "' (?)");
                insert.setBigDecimal(3, new java.math.BigDecimal(i + ".25"));
                insert.addBatch();
            }
            counts = insert.executeLargeBatch();
        }
        long[] ones = new long[300];
        Arrays.fill(ones, 1);
        assertArrayEquals(ones, counts);
        assertEquals("300", one("select count(*) from " + table));
        assertEquals("row '299' (?)", one("select label from " + table + " where id = 299"));
        assertEquals(null, one("select label from " + table + " where id = 14"));
        assertEquals("44850", one("select sum(id) from " + table));
    }

    /** The same statement, batch after batch - the way a benchmark or a loader uses it. */
    @Test
    void theStatementCanBeBatchedAgain() throws Exception {
        try (PreparedStatement insert = connection.prepareStatement(
                "insert into " + table + " (id, label) values (?, ?)")) {
            for (int round = 0; round < 3; round++) {
                for (int i = 0; i < 12; i++) {
                    insert.setInt(1, round * 100 + i);
                    insert.setString(2, "r" + round);
                    insert.addBatch();
                }
                assertEquals(12, insert.executeBatch().length);
            }
        }
        assertEquals("36", one("select count(*) from " + table));
    }

    @Test
    void insertIgnoreThatSkipsRowsSaysNoInfo() throws Exception {
        execute("insert into " + table + " (id) values (3)");
        try (PreparedStatement insert = connection.prepareStatement(
                "insert ignore into " + table + " (id) values (?)")) {
            for (int i = 0; i < 4; i++) {
                insert.setInt(1, i);
                insert.addBatch();
            }
            long[] counts = insert.executeLargeBatch();
            for (long count : counts) {
                assertEquals(Statement.SUCCESS_NO_INFO, count);
            }
        }
        assertEquals("4", one("select count(*) from " + table));
    }

    @Test
    void aFailingBlockFailsAsAWhole() throws Exception {
        try (PreparedStatement insert = connection.prepareStatement(
                "insert into " + table + " (id) values (?)")) {
            for (int i : new int[] {1, 2, 3, 2}) {
                insert.setInt(1, i);
                insert.addBatch();
            }
            java.sql.BatchUpdateException refused = assertThrows(
                    java.sql.BatchUpdateException.class, insert::executeLargeBatch);
            assertEquals(1062, refused.getErrorCode(), refused.getMessage());
            long[] failed = new long[4];
            Arrays.fill(failed, Statement.EXECUTE_FAILED);
            assertArrayEquals(failed, refused.getLargeUpdateCounts());
        }
        assertEquals("0", one("select count(*) from " + table));
    }

    /**
     * 300 rows, a duplicate in the second block of 128: the first block
     * landed and says so, the second failed as a whole, and the rows after it
     * were never sent - the counts tell a retry exactly that.
     */
    @Test
    void theCountsSayWhichBlocksLanded() throws Exception {
        try (PreparedStatement insert = connection.prepareStatement(
                "insert into " + table + " (id) values (?)")) {
            for (int i = 0; i < 300; i++) {
                insert.setInt(1, i == 200 ? 150 : i);
                insert.addBatch();
            }
            java.sql.BatchUpdateException refused = assertThrows(
                    java.sql.BatchUpdateException.class, insert::executeLargeBatch);
            long[] counts = refused.getLargeUpdateCounts();
            assertEquals(256, counts.length, "only the rows that were sent");
            for (int i = 0; i < 256; i++) {
                assertEquals(i < 128 ? 1 : Statement.EXECUTE_FAILED, counts[i], "row " + i);
            }
        }
        assertEquals("128", one("select count(*) from " + table));
    }

    @Test
    void aStatementThatIsNotAPlainInsertStillRunsRowByRow() throws Exception {
        execute("insert into " + table + " (id, amount) values (1, 1), (2, 2)");
        try (PreparedStatement update = connection.prepareStatement(
                "update " + table + " set amount = amount + ? where id = ?")) {
            update.setInt(1, 10);
            update.setInt(2, 1);
            update.addBatch();
            update.setInt(1, 20);
            update.setInt(2, 2);
            update.addBatch();
            assertArrayEquals(new int[] {1, 1}, update.executeBatch());
        }
        assertEquals("33.00", one("select sum(amount) from " + table));
    }

    private String one(String sql) throws SQLException {
        try (Statement s = connection.createStatement(); ResultSet rows = s.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }

    private void execute(String sql) throws SQLException {
        try (Statement s = connection.createStatement()) {
            s.execute(sql);
        }
    }
}
