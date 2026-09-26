package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.TransactionResolutionUnknownException;
import space.seclume.tck.BreakableRelay;
import space.seclume.tck.TestHosts;

/**
 * The third outcome of a commit, produced for real on all four.
 *
 * <p>A commit that succeeds returns; a commit the server refuses throws with
 * the server's state. The case this class is about is the one in between: the
 * COMMIT <b>reached the server and was applied</b>, and the answer never came
 * back. The client is left with a broken connection and no way to know.
 *
 * <p>The relay in front of the server makes that exact situation rather than
 * an approximation of it: requests keep flowing, answers are dropped, then
 * the connection closes. Cutting the connection outright would not do - that
 * usually kills the COMMIT before it lands, and the test would be about a
 * transaction that was never committed, which is the easy case.
 *
 * <p><b>The second half of each test is the point.</b> After the client has
 * been told "unknown", a separate connection looks, and finds the row. That
 * is what makes the new state necessary rather than pedantic: had the driver
 * reported an ordinary connection failure, the reasonable-looking response -
 * run the transaction again - would have written the row twice.
 */
@Timeout(120)
class CommitOutcomeTest {

    private record Database(String name, String scheme, int port, String database, String user,
                            String passwordFile, String options, String createTable) {

        String url(String host, int at, Path password) {
            return "jdbc:seclume:" + scheme + "://" + host + ":" + at + "/" + database
                    + "?user=" + user + options
                    + "&provider=file&path=" + password.toString().replace('\\', '/');
        }
    }

    private static final String TABLE = "zl_commit_outcome";

    static List<Database> databases() {
        return List.of(
                new Database("PostgreSQL", "postgresql", 5432, "seclume_test", "seclume_test",
                        ".local-pg-password", "&tls=off", "create table " + TABLE + " (n int)"),
                new Database("MySQL", "mysql", 3307, "seclume_test", "seclume_test",
                        ".local-mysql-password", "&tls=off", "create table " + TABLE + " (n int)"),
                new Database("SQL Server", "sqlserver", 1433, "master", "sa",
                        ".local-mssql-password", "&trustServerCertificate=true",
                        "create table " + TABLE + " (n int)"),
                new Database("Oracle", "oracle", 1521, "FREEPDB1", "seclume_test",
                        ".local-oracle-password", "",
                        "create table " + TABLE + " (n number(9))"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void aCommitWhoseAnswerIsLostIsReportedAsUnknownAndReallyWasApplied(Database database)
            throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);

        try (Connection direct = DriverManager.getConnection(database.url(host, port, password))) {
            recreate(direct, database);

            try (BreakableRelay relay = BreakableRelay.to(host, port);
                    Connection through = DriverManager.getConnection(
                            database.url("127.0.0.1", relay.port(), password))) {
                through.setAutoCommit(false);

                // The control: through the relay a commit works, so what
                // follows is the relay's doing and not a path that never did.
                insert(through, 1);
                through.commit();

                insert(through, 2);
                relay.swallowAnswers();

                SQLException thrown = assertThrows(SQLException.class, through::commit,
                        "a commit whose answer never came back returned normally");
                assertInstanceOf(TransactionResolutionUnknownException.class, thrown,
                        "the lost commit was reported as an ordinary failure: " + thrown);
                assertEquals("08007", thrown.getSQLState());
                assertInstanceOf(SQLException.class, thrown.getCause(),
                        "the connection failure underneath has to stay reachable");
            }

            // And the reason the state exists: it was applied.
            assertEquals(List.of(1, 2), rows(direct),
                    "the transaction reported as unknown was in fact committed - which is "
                            + "exactly why it must not be reported as a plain failure");
        }
    }

    /**
     * In auto-commit every statement commits itself - so a lost answer to a
     * write is a lost commit, with the COMMIT left implicit.
     *
     * <p>This is {@code ChaosBenchmark}'s "writes in doubt": the client was
     * told the write failed, and the row is there. Before, the client had no
     * way to tell that apart from a write that never landed.
     *
     * <p>Two controls beside it, because the classification is only useful
     * if it is narrow. A <b>read</b> whose answer is lost changed nothing and
     * stays an ordinary failure. And a write <b>inside a transaction</b> whose
     * answer is lost is not unknown at all: the transaction dies with the
     * connection and the server rolls it back.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void aWriteInAutoCommitWhoseAnswerIsLostIsUnknownAndAReadIsNot(Database database)
            throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);

        try (Connection direct = DriverManager.getConnection(database.url(host, port, password))) {
            recreate(direct, database);

            // The write, in auto-commit.
            try (BreakableRelay relay = BreakableRelay.to(host, port);
                    Connection through = DriverManager.getConnection(
                            database.url("127.0.0.1", relay.port(), password))) {
                insert(through, 1);                           // the control: it works
                relay.swallowAnswers();
                SQLException thrown = assertThrows(SQLException.class, () -> insert(through, 2));
                assertInstanceOf(TransactionResolutionUnknownException.class, thrown,
                        "a lost write in auto-commit was reported as an ordinary failure: "
                                + thrown);
            }
            assertEquals(List.of(1, 2), rows(direct),
                    "the write reported as unknown was in fact applied");

            // The read, in auto-commit: nothing can have changed.
            try (BreakableRelay relay = BreakableRelay.to(host, port);
                    Connection through = DriverManager.getConnection(
                            database.url("127.0.0.1", relay.port(), password))) {
                relay.swallowAnswers();
                SQLException thrown = assertThrows(SQLException.class, () -> rows(through));
                assertNotEquals(TransactionResolutionUnknownException.class, thrown.getClass(),
                        "a lost read was called a possibly applied write");
            }

            // The write inside a transaction: the outcome is known.
            try (BreakableRelay relay = BreakableRelay.to(host, port);
                    Connection through = DriverManager.getConnection(
                            database.url("127.0.0.1", relay.port(), password))) {
                through.setAutoCommit(false);
                insert(through, 3);
                relay.swallowAnswers();
                SQLException thrown = assertThrows(SQLException.class, () -> insert(through, 4));
                assertNotEquals(TransactionResolutionUnknownException.class, thrown.getClass(),
                        "a write inside a transaction was called unknown - but the "
                                + "transaction dies with the connection");
            }
            assertEquals(List.of(1, 2), rows(direct),
                    "the transaction that lost its connection was not rolled back");
        }
    }

    /** A prepared batch in auto-commit is a write as well, and takes another path. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void aBatchInAutoCommitWhoseAnswerIsLostIsUnknown(Database database) throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);

        try (Connection direct = DriverManager.getConnection(database.url(host, port, password))) {
            recreate(direct, database);
            try (BreakableRelay relay = BreakableRelay.to(host, port);
                    Connection through = DriverManager.getConnection(
                            database.url("127.0.0.1", relay.port(), password));
                    PreparedStatement batch = through.prepareStatement(
                            "insert into " + TABLE + " (n) values (?)")) {
                // A batch that works first, and not only as a control: on
                // MySQL the statement is prepared on the server by the first
                // execution. Without this the relay swallowed the answer to
                // the PREPARE, nothing had been executed, and the plain
                // failure the test then got was the right answer to a
                // different question. The first version of this test asked it.
                batch.setInt(1, 0);
                batch.addBatch();
                batch.executeBatch();

                for (int n = 1; n <= 3; n++) {
                    batch.setInt(1, n);
                    batch.addBatch();
                }
                relay.swallowAnswers();
                SQLException thrown = assertThrows(SQLException.class, batch::executeBatch);
                assertInstanceOf(TransactionResolutionUnknownException.class, thrown,
                        "a lost batch in auto-commit was reported as an ordinary failure: "
                                + thrown);
            }
        }
    }

    /**
     * Switching auto-commit on commits - and has to, even when nothing follows.
     *
     * <p>JDBC is explicit about it: calling {@code setAutoCommit(true)} during
     * a transaction commits that transaction. MySQL's driver used to announce
     * the switch and send it with the next statement, which saves a round
     * trip and is right as long as there is a next statement. When there was
     * not - switch on, close - the server saw a connection go away with a
     * transaction open and rolled it back. <b>Work the application had every
     * reason to think committed was gone</b>, without an exception anywhere.
     *
     * <p>Found by asking what the deferred switch meant for the commit
     * outcome, and then trying it: zero rows. On all four here, because the
     * other three got it right for reasons of their own and that is not the
     * same as being checked.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void switchingAutoCommitOnCommitsEvenWhenNothingFollows(Database database)
            throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);
        String url = database.url(host, port, password);

        try (Connection setup = DriverManager.getConnection(url)) {
            recreate(setup, database);
        }
        try (Connection connection = DriverManager.getConnection(url)) {
            connection.setAutoCommit(false);
            insert(connection, 7);
            connection.setAutoCommit(true);
        }
        try (Connection check = DriverManager.getConnection(url)) {
            assertEquals(List.of(7), rows(check),
                    "setAutoCommit(true) followed by close() lost the transaction");
        }
    }

    /**
     * The other direction: a commit the server <b>answered</b> keeps its own
     * state.
     *
     * <p>A deferred unique constraint is checked at commit, so the commit
     * fails with {@code 23505} and the transaction is gone - a known outcome.
     * Wrapping that as "unknown" would send somebody looking for a row that
     * cannot be there, and would hide a constraint violation behind a network
     * story. PostgreSQL only, because it is the one of the four whose
     * deferred constraints make the failure land on the commit itself.
     */
    @Test
    void aCommitTheServerRefusedKeepsTheServersState() throws Exception {
        Database postgres = databases().get(0);
        String host = hostOf(postgres);
        int port = portOf(postgres);
        Path password = passwordOf(postgres);
        reachable(host, port);

        try (Connection connection = DriverManager.getConnection(
                postgres.url(host, port, password))) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists zl_commit_deferred");
                statement.execute("create table zl_commit_deferred "
                        + "(n int unique deferrable initially deferred)");
            }
            connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement()) {
                statement.execute("insert into zl_commit_deferred values (1)");
                statement.execute("insert into zl_commit_deferred values (1)");
            }
            SQLException refused = assertThrows(SQLException.class, connection::commit);
            assertEquals("23505", refused.getSQLState(),
                    "the server's own refusal was rewritten: " + refused);
            assertNotEquals(TransactionResolutionUnknownException.class, refused.getClass());

            connection.setAutoCommit(true);
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table zl_commit_deferred");
            }
        }
    }

    // ---- fixture ---------------------------------------------------------

    private static void recreate(Connection connection, Database database) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            try {
                statement.execute("drop table " + TABLE);
            } catch (SQLException absent) {
                // Not there yet, which is the ordinary case.
            }
            statement.execute(database.createTable());
        }
    }

    private static void insert(Connection connection, int n) throws SQLException {
        try (PreparedStatement insert = connection.prepareStatement(
                "insert into " + TABLE + " (n) values (?)")) {
            insert.setInt(1, n);
            insert.executeUpdate();
        }
    }

    private static List<Integer> rows(Connection connection) throws SQLException {
        java.util.ArrayList<Integer> found = new java.util.ArrayList<>();
        try (Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery(
                        "select n from " + TABLE + " order by n")) {
            while (rows.next()) {
                found.add(rows.getInt(1));
            }
        }
        return found;
    }

    private static String key(Database database) {
        return switch (database.scheme()) {
            case "postgresql" -> "pg";
            case "sqlserver" -> "mssql";
            default -> database.scheme();
        };
    }

    private static String hostOf(Database database) {
        String host = System.getProperty("seclume." + key(database) + ".host",
                TestHosts.database());
        Assumptions.assumeTrue(host != null, "no host configured for " + database.name());
        return host;
    }

    private static int portOf(Database database) {
        return Integer.getInteger("seclume." + key(database) + ".port", database.port());
    }

    private static Path passwordOf(Database database) {
        String named = System.getProperty("seclume." + key(database) + ".passwordFile",
                database.passwordFile());
        for (Path candidate : List.of(Path.of(named), Path.of("..", named))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.abort("no " + named);
        return null;
    }

    private static void reachable(String host, int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("nothing on " + host + ":" + port);
        }
    }
}
