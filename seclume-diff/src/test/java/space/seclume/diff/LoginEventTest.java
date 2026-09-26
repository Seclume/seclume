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
import java.time.Duration;
import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

import space.seclume.tck.TestHosts;

/**
 * The login, timed apart from the connection it belongs to - on all four.
 *
 * <p>An open is three phases and one number. The connect is the network, the
 * handshake is certificates and whatever the JVM has to look up to trust one,
 * and the login is the directory <b>behind</b> the database - LDAP, PAM,
 * Kerberos, an IAM token. They are slow for different reasons and they fail
 * for different reasons, and an operator holding only {@code ConnectionOpen}
 * cannot tell which of the three is the one to go and look at.
 *
 * <p>Two things are asserted here, and the second is the one worth the file.
 *
 * <p><b>That the event fires at all, per driver.</b> The seam is different in
 * every one of the four - PostgreSQL's startup message, MySQL's handshake
 * response after the plugin is known, TDS's LOGIN7, Oracle's second O5LOGON -
 * so "it works" on one says nothing about the others. An event class that
 * nothing ever raises is worse than one that does not exist, because it reads
 * in the documentation as a feature.
 *
 * <p><b>That it is shorter than the whole open.</b> That is the claim the
 * event makes by existing: if it took as long as the connection did, it is
 * measuring the wrong thing and nobody would find out by reading the field
 * names. A login that is merely <i>not longer</i> than the open would pass a
 * test that asserted the event exists.
 */
@Timeout(300)
// Alone: it records events of the whole process, and a class running beside it
// would put its own statements and logins into the recording.
@org.junit.jupiter.api.parallel.Isolated
class LoginEventTest {

    private record Database(String name, String scheme, int port, String database, String user,
                            String passwordFile, String options, String method) {

        String url(String host, int at, Path password) {
            return "jdbc:seclume:" + scheme + "://" + host + ":" + at + "/" + database
                    + "?user=" + user + options
                    + "&provider=file&path=" + password.toString().replace('\\', '/');
        }
    }

    /**
     * The expected method per driver, and it is the server's own word.
     *
     * <p>MySQL is the only one where it is a question rather than a constant -
     * the server names a plugin and may switch part-way through - so what is
     * asserted there is that the plugin the login settled on was recorded,
     * not which one it was.
     */
    static List<Database> databases() {
        return List.of(
                new Database("PostgreSQL", "postgresql", 5432, "seclume_test", "seclume_test",
                        ".local-pg-password", "&tls=off", "scram-sha-256"),
                new Database("MySQL", "mysql", 3307, "seclume_test", "seclume_test",
                        ".local-mysql-password", "&tls=off", null),
                new Database("SQL Server", "sqlserver", 1433, "master", "sa",
                        ".local-mssql-password", "&trustServerCertificate=true", "login7"),
                new Database("Oracle", "oracle", 1521, "FREEPDB1", "seclume_test",
                        ".local-oracle-password", "", "o5logon"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void theLoginIsRecordedOnItsOwnAndIsShorterThanTheOpen(Database database,
            @TempDir Path directory) throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);
        Path file = directory.resolve("login-" + database.scheme() + ".jfr");

        try (Recording recording = new Recording()) {
            // Threshold to zero on both: against a local server a login is
            // well under the ten milliseconds JFR defaults to, and a test that
            // recorded nothing would pass every assertion it never made.
            recording.enable("space.seclume.Authentication").withThreshold(Duration.ZERO);
            recording.enable("space.seclume.ConnectionOpen").withThreshold(Duration.ZERO);
            recording.start();

            try (Connection connection = DriverManager.getConnection(
                    database.url(host, port, password))) {
                assertFalse(connection.isClosed());
            }

            recording.stop();
            recording.dump(file);
        }

        List<RecordedEvent> events = RecordingFile.readAllEvents(file);
        List<RecordedEvent> logins = of(events, "space.seclume.Authentication");
        List<RecordedEvent> opens = of(events, "space.seclume.ConnectionOpen");

        assertEquals(1, logins.size(),
                "one connection was opened, so there is one login to record: " + logins);
        assertEquals(1, opens.size(), "one connection, one open: " + opens);

        RecordedEvent login = logins.get(0);
        assertEquals(database.scheme(), login.getString("kind"));
        assertEquals(host + ":" + port, login.getString("server"));
        assertTrue(login.getBoolean("succeeded"), "the connection stood, so the login did");

        String method = login.getString("method");
        assertFalse(method == null || method.isBlank(),
                "a login that does not say what it was asked for is half the event");
        if (database.method() != null) {
            assertEquals(database.method(), method.toLowerCase(Locale.ROOT));
        }

        // The point of the event: it is a part of the open, not a copy of it.
        Duration whole = opens.get(0).getDuration();
        Duration part = login.getDuration();
        assertTrue(part.compareTo(whole) < 0,
                "the login is recorded as taking " + part + " of an open that took " + whole
                        + " - then it is measuring the open and not the login");
    }

    /**
     * And the rule that holds for every event in this project.
     *
     * <p>The method is the server's own word for what it asked for. Nothing
     * about what was sent back belongs in it - not the secret, not its length,
     * not a hash. The same question was answered the same way for the flight
     * recorder, and the reasoning does not improve by being repeated: a length
     * is a fact about a password that an attacker is glad to have.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void theEventCarriesNoNumberThatCameFromTheSecret(Database database,
            @TempDir Path directory) throws Exception {
        String host = hostOf(database);
        int port = portOf(database);
        Path password = passwordOf(database);
        reachable(host, port);
        Path file = directory.resolve("login-fields-" + database.scheme() + ".jfr");

        String secret = Files.readString(password).strip();
        Assumptions.assumeFalse(secret.isEmpty(), "the password file is empty");

        try (Recording recording = new Recording()) {
            recording.enable("space.seclume.Authentication").withThreshold(Duration.ZERO);
            recording.start();
            try (Connection connection = DriverManager.getConnection(
                    database.url(host, port, password))) {
                assertFalse(connection.isClosed());
            }
            recording.stop();
            recording.dump(file);
        }

        List<RecordedEvent> logins = of(RecordingFile.readAllEvents(file),
                "space.seclume.Authentication");
        assertFalse(logins.isEmpty(), "nothing was recorded - then this proves nothing");
        RecordedEvent login = logins.get(0);

        assertFalse(login.getString("method").contains(secret), "the method carries the secret");
        assertFalse(login.getString("server").contains(secret), "the server carries the secret");
        // The fields are four and they are named here on purpose: a fifth one
        // added later is exactly the one nobody would think to check, and this
        // fails when that happens.
        assertEquals(List.of("kind", "server", "method", "succeeded"),
                login.getFields().stream()
                        .map(jdk.jfr.ValueDescriptor::getName)
                        .filter(name -> !name.startsWith("start") && !name.startsWith("duration")
                                && !name.equals("eventThread") && !name.equals("stackTrace"))
                        .toList(),
                "the event grew a field - is it derived from the credential?");
    }

    private static List<RecordedEvent> of(List<RecordedEvent> events, String name) {
        return events.stream()
                .filter(event -> event.getEventType().getName().equals(name))
                .toList();
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
