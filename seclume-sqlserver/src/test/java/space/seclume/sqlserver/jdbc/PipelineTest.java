package space.seclume.sqlserver.jdbc;

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
 * One round trip for a unit of work, on SQL Server.
 *
 * <p>The block existed here and saved nothing: the driver said so in its own
 * javadoc - "allowed here and saves nothing - yet". What changed is that the
 * machinery it needed was already in the module, used by {@code executeBatch}:
 * TDS carries several RPCs in one message, separated by {@code 0xff}. The
 * batch bundles one statement with many values; the block bundles many
 * statements.
 *
 * <p><b>Measured in round trips rather than milliseconds.</b> See
 * {@link RoundTrips}: the count does not depend on the network, so it says the
 * same thing on this machine and in production - and it is the number the
 * whole exercise is about. A test that measured time would pass on a loopback
 * connection whatever the driver did.
 */
@Timeout(180)
class PipelineTest {

    private String url;
    private String host;
    private int port;

    @BeforeEach
    void findTheServer() throws Exception {
        host = System.getProperty("seclume.mssql.host", TestHosts.database());
        Assumptions.assumeTrue(host != null, "no SQL Server host configured");
        port = Integer.getInteger("seclume.mssql.port", 1433);
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mssql-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no SQL Server on " + host + ":" + port);
        }
        url = "jdbc:seclume:sqlserver://" + host + ":" + port + "/master"
                + "?user=sa&trustServerCertificate=true&provider=file&path="
                + password.toString().replace('\\', '/');

        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            statement.execute("if object_id('dbo.pipeline_demo') is not null "
                    + "drop table dbo.pipeline_demo");
            statement.execute("create table dbo.pipeline_demo (id int primary key, note nvarchar(40))");
        }
    }

    @AfterEach
    void cleanUp() throws Exception {
        if (url == null) {
            return;
        }
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            statement.execute("if object_id('dbo.pipeline_demo') is not null "
                    + "drop table dbo.pipeline_demo");
        }
    }

    /**
     * Eight inserts, and what they cost with and without the block.
     *
     * <p>The assertion is a comparison rather than a fixed number: what the
     * login and the first compilation cost is not the point, and pinning it
     * would make this test fail every time something unrelated changed.
     */
    @Test
    void aBlockCostsFewerRoundTripsThanTheSameStatementsWithoutOne() throws Exception {
        long without = insertEight(false);
        long with = insertEight(true);

        System.out.println("[pipeline] eight inserts: " + without
                + " round trips without the block, " + with + " with it");
        assertTrue(with < without,
                "the block saved nothing: " + with + " round trips against " + without);
        // Eight executions, one message: what is left is the login, the first
        // compilation and the transaction. Seven saved out of eight is the
        // shape to expect, and a good deal less would mean the grouping broke
        // apart somewhere.
        assertTrue(without - with >= 6,
                "expected the eight to travel as one, saved only " + (without - with)
                        + " round trips (" + with + " against " + without + ")");
    }

    /** And the rows are actually there, in the right order, exactly once. */
    @Test
    @SuppressWarnings("try")   // the block is used for its effect, not its value
    void everythingInTheBlockReachesTheTable() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            connection.setAutoCommit(false);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into dbo.pipeline_demo (id, note) values (?, ?)")) {
                try (Pipeline unit = Pipeline.open(connection)) {
                    for (int i = 1; i <= 8; i++) {
                        insert.setInt(1, i);
                        insert.setString(2, "row " + i);
                        long count = insert.executeUpdate();
                        if (i == 1) {
                            // The first execution compiles the statement and
                            // comes back with a handle, so it has a real count
                            // - that round trip is the one nobody can avoid.
                            assertEquals(1, count, "the first execution reports what it did");
                        } else {
                            assertEquals(Statement.SUCCESS_NO_INFO, count,
                                    "a buffered write must not invent a count");
                        }
                    }
                }
            }
            connection.commit();

            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery(
                            "select count(*), min(id), max(id) from dbo.pipeline_demo")) {
                assertTrue(rows.next());
                assertEquals(8, rows.getInt(1), "not every buffered insert reached the table");
                assertEquals(1, rows.getInt(2));
                assertEquals(8, rows.getInt(3));
            }
            connection.commit();
        }
    }

    /**
     * A query inside the block sends what is buffered first.
     *
     * <p>The promise that makes the block safe to use: the moment anything
     * really needs an answer, everything buffered goes out. Without it a
     * select would look past writes that the application has already made.
     */
    @Test
    @SuppressWarnings("try")   // the block is used for its effect, not its value
    void aQueryInsideTheBlockSeesWhatWasBufferedBeforeIt() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            connection.setAutoCommit(false);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into dbo.pipeline_demo (id, note) values (?, ?)");
                    Statement query = connection.createStatement()) {
                try (Pipeline unit = Pipeline.open(connection)) {
                    for (int i = 1; i <= 3; i++) {
                        insert.setInt(1, i);
                        insert.setString(2, "row " + i);
                        insert.executeUpdate();
                    }
                    try (ResultSet rows = query.executeQuery(
                            "select count(*) from dbo.pipeline_demo")) {
                        assertTrue(rows.next());
                        assertEquals(3, rows.getInt(1),
                                "the query did not see the writes buffered before it");
                    }
                }
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

    /** Eight inserts, counted in round trips. */
    @SuppressWarnings("try")   // the block is used for its effect, not its value
    private long insertEight(boolean pipelined) throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
                Statement clean = connection.createStatement()) {
            clean.execute("delete from dbo.pipeline_demo");
            connection.setAutoCommit(false);

            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into dbo.pipeline_demo (id, note) values (?, ?)")) {
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
