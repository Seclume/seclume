package space.seclume.diff;

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
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import jdk.jfr.Recording;
import jdk.jfr.ValueDescriptor;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedObject;
import jdk.jfr.consumer.RecordingFile;

import space.seclume.tck.TestHosts;

/**
 * What reaches a Flight Recorder recording, on all four drivers.
 *
 * <p>The PostgreSQL module has had this test since the events were built; the
 * other three never had it, although the risk is per driver. Each one hands
 * {@code Observed.endQuery} a statement text and a
 * {@link space.seclume.QueryFingerprint.Dialect}, and the fingerprint is only
 * as good as that pairing: a driver passing the wrong dialect, or passing a
 * rewritten statement instead of the one the application wrote, would put
 * values into a recording while every other test stayed green.
 *
 * <p><b>Why a recording is worse than a heap.</b> It is written to a file,
 * kept for weeks and handed to whoever is debugging - a longer life and a
 * wider audience than a heap dump, which this project goes to considerable
 * lengths about. A JFR event carrying a bind value would be a leak with a
 * nice user interface.
 *
 * <p>So the test plants an unmistakable value twice - once as a literal in the
 * statement text and once as a bind parameter - and then walks <b>every field
 * of every recorded event</b> looking for it. Not the fields expected to be
 * dangerous: the ones somebody adds later are exactly the ones nobody would
 * think to check.
 */
@Timeout(300)
// Alone: it records events of the whole process, and a class running beside it
// would put its own statements and logins into the recording.
@org.junit.jupiter.api.parallel.Isolated
class JfrNoValuesTest {

    /** Long enough that finding it anywhere means something. */
    private static final String SECRET_VALUE = "hunter2swordfish-JFR-4d91ac";

    private record Database(String name, String scheme, int port, String database, String user,
                            String passwordFile, String options, String dual) {

        String url(String host, int at, Path password) {
            return "jdbc:seclume:" + scheme + "://" + host + ":" + at + "/" + database
                    + "?user=" + user + options
                    + "&provider=file&path=" + password.toString().replace('\\', '/');
        }

        /** What this database wants after a select without a table. */
        String selectOne(String expression) {
            return "oracle".equals(scheme)
                    ? "select " + expression + " from dual"
                    : "select " + expression;
        }
    }

    static List<Database> databases() {
        return List.of(
                new Database("PostgreSQL", "postgresql", 5432, "seclume_test", "seclume_test",
                        ".local-pg-password", "&tls=off", "dual"),
                new Database("MySQL", "mysql", 3307, "seclume_test", "seclume_test",
                        ".local-mysql-password", "&tls=off", "dual"),
                new Database("SQL Server", "sqlserver", 1433, "master", "sa",
                        ".local-mssql-password", "&trustServerCertificate=true", "dual"),
                new Database("Oracle", "oracle", 1521, "FREEPDB1", "seclume_test",
                        ".local-oracle-password", "", "dual"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void noValueEverReachesTheRecording(Database database, @TempDir Path directory)
            throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);
        Path file = directory.resolve("seclume-" + database.scheme() + ".jfr");

        try (Recording recording = new Recording()) {
            // Threshold to zero: ten milliseconds makes this a slow-query
            // event, which is right in production and records nothing at all
            // against a local server.
            recording.enable("space.seclume.Query").withThreshold(Duration.ZERO);
            recording.enable("space.seclume.ConnectionOpen");
            recording.enable("space.seclume.StatementCache");
            recording.enable("space.seclume.CredentialRotation");
            recording.enable("space.seclume.TlsHandshake");
            recording.enable("space.seclume.Failover");
            recording.start();

            try (Connection connection = DriverManager.getConnection(
                    database.url(host, port, password))) {
                // As a literal in the text, which is what the fingerprint has
                // to mask - and the masking is dialect-specific, which is the
                // part that can only be wrong per driver.
                try (Statement statement = connection.createStatement();
                        ResultSet rows = statement.executeQuery(
                                database.selectOne("'" + SECRET_VALUE + "'"))) {
                    assertTrue(rows.next());
                }
                // And as a bind value, which must not appear either - a
                // parameter is exactly what a slow-query log is not allowed to
                // carry.
                try (PreparedStatement statement = connection.prepareStatement(
                        database.selectOne("?"))) {
                    statement.setString(1, SECRET_VALUE);
                    try (ResultSet rows = statement.executeQuery()) {
                        assertTrue(rows.next());
                    }
                }
            }

            recording.stop();
            recording.dump(file);
        }

        List<RecordedEvent> events = RecordingFile.readAllEvents(file);

        // The control: without it an empty search would prove only that
        // nothing was recorded at all.
        List<RecordedEvent> queries = events.stream()
                .filter(event -> event.getEventType().getName().equals("space.seclume.Query"))
                .toList();
        assertFalse(queries.isEmpty(), "no query was recorded - then this proves nothing");
        assertTrue(queries.stream().anyMatch(event -> event.getString("fingerprint") != null
                        && event.getString("fingerprint").contains("?")),
                "no fingerprint masked anything, which is what the masking is for: "
                        + queries.stream().map(e -> e.getString("fingerprint")).toList());

        List<String> leaked = new ArrayList<>();
        for (RecordedEvent event : events) {
            for (String text : everyString(event)) {
                if (text.toLowerCase(Locale.ROOT).contains(SECRET_VALUE.toLowerCase(Locale.ROOT))) {
                    leaked.add(event.getEventType().getName() + ": " + text);
                }
            }
        }
        assertTrue(leaked.isEmpty(), () -> "a value reached the recording:\n  "
                + String.join("\n  ", leaked));
    }

    /** Every string in an event, whatever it is called and however nested. */
    private static List<String> everyString(RecordedObject object) {
        List<String> found = new ArrayList<>();
        for (ValueDescriptor field : object.getFields()) {
            Object value = object.getValue(field.getName());
            if (value instanceof String text) {
                found.add(text);
            } else if (value instanceof RecordedObject nested) {
                found.addAll(everyString(nested));
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
