package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.Pipeline;
import space.seclume.RoundTrips;
import space.seclume.tck.TestHosts;

/**
 * One round trip for a unit of work, on PostgreSQL.
 *
 * <p>The block has worked here since it was built - and had no test of its
 * own, which was noticed only when the same block was built for the other two
 * drivers. That is the pattern this suite keeps running into: a promise that
 * holds today because nobody has touched the code, rather than because
 * something checks it.
 *
 * <p>PostgreSQL's shape is the one the extended query protocol was made for:
 * Parse/Bind/Execute go out without a {@code Sync} in between, so several
 * statements travel together and the answers come back in order. Measured in
 * round trips rather than milliseconds - see {@link RoundTrips}, the count is
 * the same on a laptop and in production.
 */
@Timeout(180)
class PipelineTest {

    private String url;

    @BeforeEach
    void findTheServer() throws Exception {
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
                + password.toString().replace('\\', '/');

        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists pipeline_demo");
            statement.execute("create table pipeline_demo (id int primary key, note text)");
        }
    }

    @AfterEach
    void cleanUp() throws Exception {
        if (url == null) {
            return;
        }
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists pipeline_demo");
        }
    }

    /** Eight inserts, and what they cost with and without the block. */
    @Test
    void aBlockCostsFewerRoundTripsThanTheSameStatementsWithoutOne() throws Exception {
        long without = insertEight(false);
        long with = insertEight(true);

        System.out.println("[postgresql] eight inserts: " + without
                + " round trips without the block, " + with + " with it");
        assertTrue(with < without,
                "the block saved nothing: " + with + " round trips against " + without);
        assertTrue(without - with >= 6,
                "expected the eight to travel together, saved only " + (without - with)
                        + " round trips (" + with + " against " + without + ")");
    }

    /** And everything in it reaches the table, exactly once. */
    @Test
    @SuppressWarnings("try")   // the block is used for its effect, not its value
    void everythingInTheBlockReachesTheTable() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            connection.setAutoCommit(false);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into pipeline_demo (id, note) values (?, ?)")) {
                try (Pipeline unit = Pipeline.open(connection)) {
                    for (int i = 1; i <= 8; i++) {
                        insert.setInt(1, i);
                        insert.setString(2, "row " + i);
                        assertEquals(Statement.SUCCESS_NO_INFO, insert.executeUpdate(),
                                "a buffered write must not invent a count");
                    }
                }
            }
            connection.commit();

            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery(
                            "select count(*), min(id), max(id) from pipeline_demo")) {
                assertTrue(rows.next());
                assertEquals(8, rows.getInt(1), "not every buffered insert reached the table");
                assertEquals(1, rows.getInt(2));
                assertEquals(8, rows.getInt(3));
            }
            connection.commit();
        }
    }

    /** A query inside the block sends what is buffered first. */
    @Test
    @SuppressWarnings("try")   // the block is used for its effect, not its value
    void aQueryInsideTheBlockSeesWhatWasBufferedBeforeIt() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            connection.setAutoCommit(false);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into pipeline_demo (id, note) values (?, ?)");
                    Statement query = connection.createStatement()) {
                try (Pipeline unit = Pipeline.open(connection)) {
                    for (int i = 1; i <= 3; i++) {
                        insert.setInt(1, i);
                        insert.setString(2, "row " + i);
                        insert.executeUpdate();
                    }
                    try (ResultSet rows = query.executeQuery(
                            "select count(*) from pipeline_demo")) {
                        assertTrue(rows.next());
                        assertEquals(3, rows.getInt(1),
                                "the query did not see the writes buffered before it");
                    }
                }
            }
            connection.rollback();
        }
    }

    /**
     * A failure inside the block says which statement it was.
     *
     * <p>The part that is easy to get wrong and impossible to act on when it
     * is: a block of eight inserts that reports only that something failed
     * leaves the caller to find out by reading the table.
     */
    @Test
    @SuppressWarnings("try")   // the block is used for its effect, not its value
    void aFailureInTheBlockNamesTheStatement() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            connection.setAutoCommit(false);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into pipeline_demo (id, note) values (?, ?)")) {
                SQLException failed = assertThrows(SQLException.class, () -> {
                    try (Pipeline unit = Pipeline.open(connection)) {
                        for (int i = 1; i <= 3; i++) {
                            insert.setInt(1, 1);          // the same key every time
                            insert.setString(2, "row " + i);
                            insert.executeUpdate();
                        }
                    }
                });
                assertTrue(String.valueOf(failed.getMessage()).contains("insert into"),
                        "the failure should name the statement: " + failed.getMessage());
            }
            connection.rollback();
        }
    }

    /** Outside a transaction the block is refused, and the message says why. */
    @Test
    void theBlockNeedsATransaction() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            connection.setAutoCommit(true);
            SQLException refused = assertThrows(SQLException.class,
                    () -> Pipeline.open(connection));
            assertTrue(refused.getMessage().contains("auto-commit"),
                    "the refusal should say what to do: " + refused.getMessage());
        }
    }

    @SuppressWarnings("try")   // the block is used for its effect, not its value
    private long insertEight(boolean pipelined) throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
                Statement clean = connection.createStatement()) {
            clean.execute("delete from pipeline_demo");
            connection.setAutoCommit(false);

            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into pipeline_demo (id, note) values (?, ?)")) {
                long before = RoundTrips.of(connection);
                if (pipelined) {
                    try (Pipeline unit = Pipeline.open(connection)) {
                        write(insert);
                    }
                } else {
                    write(insert);
                }
                long spent = RoundTrips.of(connection) - before;
                connection.commit();
                return spent;
            }
        }
    }

    private static void write(PreparedStatement insert) throws SQLException {
        for (int i = 1; i <= 8; i++) {
            insert.setInt(1, i);
            insert.setString(2, "row " + i);
            insert.executeUpdate();
        }
    }
}
