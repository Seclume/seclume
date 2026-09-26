package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.jfr.Observed;
import space.seclume.jfr.StatementListener;
import space.seclume.tck.TestHosts;

/**
 * Every driver tells the listener, and tells it the same thing.
 *
 * <p>{@link StatementListener} is the one hook this project has in the
 * statement path - it exists because a trace span belongs to the request that
 * caused it and cannot be made afterwards from a recording. A hook that three
 * drivers out of four call is worse than none: the traces would be complete
 * for some databases and silently missing for others, which is how somebody
 * concludes the database was not involved.
 *
 * <p>So this runs the same two statements against all four and asks that each
 * one produced exactly what the others did - a span per statement, the
 * fingerprint and not the text, the row count, and the database's own name.
 * The listener here is four lines and has nothing to do with OpenTelemetry:
 * what is being checked is the drivers, not the consumer.
 */
@Timeout(300)
// Alone: it records events of the whole process, and a class running beside it
// would put its own statements and logins into the recording.
@org.junit.jupiter.api.parallel.Isolated
class StatementListenerTest {

    /** A value that has no business being in anything the listener sees. */
    private static final String SECRET_VALUE = "hunter2-listener-9f31c4";

    private record Seen(String kind, String fingerprint, long rows, boolean failed) {
    }

    /** Four lines, and every one of them is the contract. */
    private static final class Recorder implements StatementListener {

        private final List<Seen> seen = new CopyOnWriteArrayList<>();

        @Override
        public Span begin(String kind) {
            return (fingerprint, rows, failed) ->
                    seen.add(new Seen(kind, fingerprint, rows, failed));
        }
    }

    private final Recorder recorder = new Recorder();

    @AfterEach
    void removeTheListener() {
        Observed.listen(null);
    }

    private record Database(String name, String scheme, int port, String database, String user,
                            String passwordFile, String options) {

        String url(String host, int at, Path password) {
            return "jdbc:seclume:" + scheme + "://" + host + ":" + at + "/" + database
                    + "?user=" + user + options
                    + "&provider=file&path=" + password.toString().replace('\\', '/');
        }

        String selectOne(String expression) {
            return "oracle".equals(scheme)
                    ? "select " + expression + " from dual"
                    : "select " + expression;
        }
    }

    static List<Database> databases() {
        return List.of(
                new Database("PostgreSQL", "postgresql", 5432, "seclume_test", "seclume_test",
                        ".local-pg-password", "&tls=off"),
                new Database("MySQL", "mysql", 3307, "seclume_test", "seclume_test",
                        ".local-mysql-password", "&tls=off"),
                new Database("SQL Server", "sqlserver", 1433, "master", "sa",
                        ".local-mssql-password", "&trustServerCertificate=true"),
                new Database("Oracle", "oracle", 1521, "FREEPDB1", "seclume_test",
                        ".local-oracle-password", ""));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void theDriverTellsTheListenerAboutEveryStatement(Database database) throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);

        Observed.listen(recorder);
        try (Connection connection = DriverManager.getConnection(
                database.url(host, port, password))) {
            // A literal in the text, which the fingerprint has to mask.
            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery(
                            database.selectOne("'" + SECRET_VALUE + "'"))) {
                assertTrue(rows.next());
            }
            // And a bind value, which travels a different route entirely.
            try (PreparedStatement statement = connection.prepareStatement(
                    database.selectOne("?"))) {
                statement.setString(1, SECRET_VALUE);
                try (ResultSet rows = statement.executeQuery()) {
                    assertTrue(rows.next());
                }
            }
        }

        List<Seen> seen = List.copyOf(recorder.seen);
        assertTrue(seen.size() >= 2,
                database.name() + " told the listener about " + seen.size()
                        + " statements, and two were run");

        for (Seen one : seen) {
            assertEquals(database.scheme(), one.kind(),
                    "the driver named itself something else: " + one.kind());
            assertFalse(one.fingerprint().contains(SECRET_VALUE),
                    "a value reached the listener: " + one.fingerprint());
        }

        // A select of one expression returns one row, whichever route it took.
        assertTrue(seen.stream().anyMatch(one -> one.rows() == 1),
                database.name() + " reported no statement with a row: " + seen);
        assertTrue(seen.stream().noneMatch(Seen::failed),
                "nothing failed here, and something says it did: " + seen);
    }

    /** Without a listener nothing is built and nothing is computed. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void withoutAListenerTheDriverSaysNothing(Database database) throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);

        // Deliberately not installed. The control for the test above: if the
        // recorder filled up anyway, the one above would be proving nothing
        // about the listener being reached.
        try (Connection connection = DriverManager.getConnection(
                database.url(host, port, password));
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery(database.selectOne("1"))) {
            assertTrue(rows.next());
        }
        assertTrue(recorder.seen.isEmpty(),
                "a listener that was never installed was told about " + recorder.seen);
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
