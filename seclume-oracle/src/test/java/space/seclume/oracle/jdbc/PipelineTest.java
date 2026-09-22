package space.seclume.oracle.jdbc;

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
import space.seclume.tck.BreakableRelay;
import space.seclume.tck.TestHosts;

/**
 * One trip for a unit of work, on Oracle - and it is a different trip than on
 * SQL Server.
 *
 * <p>TDS carries several calls in one message, so the round trips themselves
 * disappear and a counter shows it. <b>Oracle numbers every call and answers
 * each one</b>, so the calls still travel separately; what the block removes
 * is the waiting between them. The round trip counter reports the same number
 * either way, which is a limit of the counter rather than of the block: it
 * counts answers read, not time spent waiting for the first byte of each.
 *
 * <p>So this measures what there is to measure - <b>time over a slow line</b>.
 * Ten milliseconds each way through a relay, an ordinary distance between an
 * application server and its database. On a loopback connection the difference
 * disappears into the noise, which is exactly why a test that measured there
 * would prove nothing.
 */
@Timeout(240)
class PipelineTest {

    private String url;
    private String host;
    private int port;
    private String service;
    private String user;
    private Path password;

    @BeforeEach
    void findTheServer() throws Exception {
        host = System.getProperty("seclume.oracle.host", TestHosts.database());
        Assumptions.assumeTrue(host != null, "no Oracle host configured");
        port = Integer.getInteger("seclume.oracle.port", 1521);
        service = System.getProperty("seclume.oracle.service", "FREEPDB1");
        user = System.getProperty("seclume.oracle.user", "seclume_test");
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no Oracle on " + host + ":" + port);
        }
        url = url(host, port);
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            statement.execute("begin execute immediate 'drop table pipeline_demo'; "
                    + "exception when others then null; end;");
            statement.execute("create table pipeline_demo (id number primary key, "
                    + "note varchar2(40))");
        }
    }

    private String url(String at, int atPort) {
        return "jdbc:seclume:oracle://" + at + ":" + atPort + "/" + service
                + "?user=" + user + "&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    @AfterEach
    void cleanUp() throws Exception {
        if (url == null) {
            return;
        }
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            statement.execute("begin execute immediate 'drop table pipeline_demo'; "
                    + "exception when others then null; end;");
        }
    }

    /**
     * What the block is worth, over a line that has a distance in it.
     *
     * <p>The assertion is deliberately loose - a factor of two rather than the
     * factor of four that was measured - because this runs on whatever machine
     * happens to have the servers. What it pins is the claim: the block
     * removes most of the waiting, and if it ever stops doing that the test
     * says so.
     */
    @Test
    @SuppressWarnings("try")   // the block is used for its effect, not its value
    void overASlowLineTheBlockRemovesMostOfTheWaiting() throws Exception {
        try (BreakableRelay relay = BreakableRelay.to(host, port)) {
            String slow = url("127.0.0.1", relay.port());
            try (Connection connection = DriverManager.getConnection(slow)) {
                connection.setAutoCommit(false);
                try (PreparedStatement insert = connection.prepareStatement(
                        "insert into pipeline_demo (id, note) values (?, ?)")) {

                    relay.delay(10);
                    long startPlain = System.nanoTime();
                    write(insert, 1);
                    long plain = (System.nanoTime() - startPlain) / 1_000_000;
                    connection.rollback();

                    long startBlock = System.nanoTime();
                    try (Pipeline unit = Pipeline.open(connection)) {
                        write(insert, 101);
                    }
                    long block = (System.nanoTime() - startBlock) / 1_000_000;
                    connection.rollback();
                    relay.delay(0);

                    System.out.println("[oracle] over a 10 ms line, eight inserts: "
                            + plain + " ms one at a time, " + block + " ms in a block");
                    assertTrue(block * 2 < plain,
                            "the block saved little: " + block + " ms against " + plain + " ms");
                }
            }
        }
    }

    /** And everything in the block reaches the table, exactly once. */
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
                                "a call whose answer nobody has read cannot report a count");
                    }
                }
            }
            connection.commit();

            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery(
                            "select count(*), min(id), max(id) from pipeline_demo")) {
                assertTrue(rows.next());
                assertEquals(8, rows.getInt(1), "not every insert in the block reached the table");
                assertEquals(1, rows.getInt(2));
                assertEquals(8, rows.getInt(3));
            }
            connection.commit();
        }
    }

    /**
     * A query inside the block reads the outstanding answers first.
     *
     * <p>On Oracle this is sharper than on SQL Server. The calls are already
     * on the wire, so a query that did not read their answers first would be
     * handed <b>the first outstanding answer</b> - somebody else's result,
     * with no error anywhere. That is why every call goes through one place
     * that flushes; see {@code OracleSession.nextCall}.
     */
    @Test
    @SuppressWarnings("try")   // the block is used for its effect, not its value
    void aQueryInsideTheBlockSeesWhatWasSentBeforeIt() throws Exception {
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
                                "the query did not see the writes sent before it");
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

    private static void write(PreparedStatement insert, int from) throws SQLException {
        for (int i = 0; i < 8; i++) {
            insert.setInt(1, from + i);
            insert.setString(2, "row " + (from + i));
            insert.executeUpdate();
        }
    }
}
