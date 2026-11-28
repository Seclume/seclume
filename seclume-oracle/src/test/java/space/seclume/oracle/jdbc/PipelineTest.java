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
import space.seclume.tck.TestHosts;

/**
 * The block on Oracle: accepted, correct, and - for now - no faster.
 *
 * <p>It used to send the calls without waiting and save the waiting between
 * them: eight inserts over a line with ten milliseconds each way took 199 ms
 * one at a time and 46 ms in a block, and a test here held it to a factor of
 * two. That was calls in flight that the server had not been told of, and
 * with many different statement texts the server refused them at random with
 * {@code ORA-03146} and dropped the ones behind them -
 * {@link #manyDifferentTextsInOneBlockAllArrive} is that case. Oracle's own
 * pipelining is a mode the client announces; until the driver speaks it,
 * each call is answered before the next goes out, and what is tested here is
 * that the block keeps its word: every row arrives, a refusal is named.
 */
@Timeout(240)
@org.junit.jupiter.api.parallel.Isolated
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
                + "?tls=off&user=" + user + "&provider=file&path="
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
     * 130 inserts over 97 different texts, one bind each, in one block.
     *
     * <p>With calls in flight, Oracle 23.26 Free refused one of these with
     * {@code ORA-03146: invalid buffer length for TTC field} - the 1st, the
     * 15th, the 45th or the 75th, from run to run - and dropped every call
     * behind it. One text repeated never showed it, which is why the eight
     * inserts of the tests before did not.
     */
    @Test
    @SuppressWarnings("try")   // the block is used for its effect, not its value
    void manyDifferentTextsInOneBlockAllArrive() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            connection.setNetworkTimeout(Runnable::run, 60_000);
            connection.setAutoCommit(false);
            try (Pipeline unit = Pipeline.open(connection)) {
                for (int i = 1; i <= 130; i++) {
                    try (PreparedStatement insert = connection.prepareStatement(
                            "insert into pipeline_demo (id, note) values (?, 'text " + (i % 97)
                                    + "')")) {
                        insert.setInt(1, i);
                        insert.executeUpdate();
                    }
                }
            }
            connection.commit();
            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery(
                            "select count(*), count(distinct note) from pipeline_demo")) {
                assertTrue(rows.next());
                assertEquals(130, rows.getInt(1), "not every insert of the block arrived");
                assertEquals(97, rows.getInt(2));
            }
            connection.commit();
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

    /**
     * Twice as many calls in one block as the server allows open cursors.
     *
     * <p>Every pipelined call was sent on a fresh cursor and none of them was
     * ever closed, so the three hundredth ended in {@code ORA-01000} - and
     * nobody heard of it, because the answers in the block were read and not
     * looked at: the block ended as if every row had arrived. Found by a
     * benchmark whose next statement outside the block met the error.
     *
     * <p>One text over and over, which runs on the cached cursor, and then
     * more distinct texts than the cache holds, which parse afresh and push
     * each other out of it while their calls are still in flight.
     */
    @Test
    @SuppressWarnings("try")   // the block is used for its effect, not its value
    void moreCallsInTheBlockThanTheServerAllowsCursors() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            // An answer that never comes fails the test here, with what was
            // waited for, rather than at the class's timeout.
            connection.setNetworkTimeout(Runnable::run, 60_000);
            int calls = openCursors(connection) * 2;
            connection.setAutoCommit(false);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into pipeline_demo (id, note) values (?, ?)")) {
                try (Pipeline unit = Pipeline.open(connection)) {
                    for (int i = 1; i <= calls; i++) {
                        insert.setInt(1, i);
                        insert.setString(2, "row " + i);
                        insert.executeUpdate();
                    }
                }
            }
            try (Pipeline unit = Pipeline.open(connection)) {
                for (int i = 1; i <= calls; i++) {
                    // Ninety-seven texts, more than the cursor cache keeps.
                    try (PreparedStatement insert = connection.prepareStatement(
                            "insert into pipeline_demo (id, note) values (?, 'text "
                                    + (i % 97) + "')")) {
                        insert.setInt(1, calls + i);
                        insert.executeUpdate();
                    }
                }
            }
            connection.commit();

            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery(
                            "select count(*), count(distinct note) from pipeline_demo "
                                    + "where note like 'text %'")) {
                assertTrue(rows.next());
                assertEquals(calls, rows.getInt(1), "not every call of the second block arrived");
                assertEquals(97, rows.getInt(2));
            }
            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery("select count(*) from pipeline_demo")) {
                assertTrue(rows.next());
                assertEquals(2 * calls, rows.getInt(1), "not every call of the two blocks arrived");
            }
            connection.commit();
        }
    }

    /**
     * A call the server refuses inside the block is reported - with its
     * place, its text, the exception it would have raised outside, and what
     * became of the calls behind it.
     *
     * <p>Before, the block was not told of the refusal at all: its answer was
     * read, its count kept as a zero, and the block ended as if every row had
     * arrived. The calls behind it are not sent once it has been refused -
     * the exception leaves the block where it was raised.
     *
     * <p>The text was run once before the block, so its calls go out on the
     * cached cursor; the refused one takes that cursor out of the cache. The
     * connection is fine afterwards, and out of the block.
     */
    @Test
    @SuppressWarnings("try")   // the block is used for its effect, not its value
    void aRefusedCallInTheBlockIsReportedWithItsPlace() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            connection.setNetworkTimeout(Runnable::run, 60_000);
            connection.setAutoCommit(false);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into pipeline_demo (id, note) values (?, ?)")) {
                insert.setInt(1, 100);
                insert.setString(2, "before");
                assertEquals(1, insert.executeUpdate());

                SQLException refused = assertThrows(SQLException.class, () -> {
                    try (Pipeline unit = Pipeline.open(connection)) {
                        int[] keys = {1, 1, 2, 3};          // the second one is a duplicate
                        for (int key : keys) {
                            insert.setInt(1, key);
                            insert.setString(2, "in the block");
                            insert.executeUpdate();
                        }
                    }
                });
                assertTrue(refused instanceof java.sql.SQLIntegrityConstraintViolationException,
                        "a duplicate key is the same exception inside the block as outside: "
                                + refused);
                assertEquals(1, refused.getErrorCode(), refused.getMessage());
                assertTrue(refused.getMessage().contains("statement 2 of the pipeline block"),
                        refused.getMessage());
                assertTrue(refused.getMessage().contains("insert into pipeline_demo"),
                        refused.getMessage());
                assertTrue(refused.getMessage().contains("the statements before it ran"),
                        "the message has to say what became of the others: "
                                + refused.getMessage());

                // Out of the block: a count again, not SUCCESS_NO_INFO.
                insert.setInt(1, 4);
                insert.setString(2, "after");
                assertEquals(1, insert.executeUpdate());
                for (int i = 0; i < 20; i++) {
                    insert.setInt(1, 200 + i);
                    insert.setString(2, "after");
                    assertEquals(1, insert.executeUpdate());
                }
            }
            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery(
                            "select listagg(id, ',') within group (order by id) from pipeline_demo "
                                    + "where id in (1, 2, 3, 4, 100)")) {
                assertTrue(rows.next());
                assertEquals("1,4,100", rows.getString(1),
                        "the call before the refused one stays in the transaction, the two "
                                + "behind it were never sent");
            }
            connection.rollback();
        }
    }

    /** What the server allows - read rather than assumed, as in CursorReturnTest. */
    private static int openCursors(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery(
                        "select value from v$parameter where name = 'open_cursors'")) {
            Assumptions.assumeTrue(rows.next(), "cannot read open_cursors on this server");
            int allowed = rows.getInt(1);
            Assumptions.assumeTrue(allowed > 0 && allowed <= 5000,
                    "open_cursors is " + allowed + " - too large to reach in a test");
            return allowed;
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
}
