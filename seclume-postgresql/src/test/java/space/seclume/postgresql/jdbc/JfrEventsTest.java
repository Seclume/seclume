package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedObject;
import jdk.jfr.consumer.RecordingFile;
import jdk.jfr.ValueDescriptor;

import space.seclume.tck.TestHosts;

/**
 * The events, recorded for real - and searched for what must not be in them.
 *
 * <p>Two assertions, and they are not equally important.
 *
 * <p>The first is that the events appear at all and say something useful. A
 * fingerprint that is empty, a connection event with no server, a query event
 * that never fires: each of those makes the feature worthless and none of
 * them would be noticed without a recording to read.
 *
 * <p>The second is the one this class exists for. <b>A recording is written
 * to a file, kept for weeks and handed to whoever is debugging.</b> That is a
 * longer life and a wider audience than a heap dump, which this project goes
 * to considerable lengths about - so a value that reaches a JFR event is
 * worse, not better, than one that reaches the heap. The test therefore
 * plants an unmistakable string in a statement and then walks <em>every field
 * of every recorded event</em> looking for it, rather than checking the
 * fields it expects to be dangerous. The ones somebody adds later are exactly
 * the ones that would not be checked.
 */
@Timeout(120)
class JfrEventsTest {

    private static final String SECRET = "hunter2swordfishXY";

    /** A line break and an indent, as a constant so no tool has to escape it. */
    private static final String NEWLINE_INDENT = System.lineSeparator() + "  ";

    private static Path fixture() {
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no PostgreSQL password file");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(TestHosts.postgres(),
                    TestHosts.postgresPort()), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no PostgreSQL on " + TestHosts.postgres());
        }
        return password;
    }

    private static String url(Path password) {
        return "jdbc:seclume:postgresql://" + TestHosts.postgres() + ":"
                + TestHosts.postgresPort() + "/seclume_test?user=seclume_test&tls=off"
                + "&provider=file&path=" + password.toString().replace('\\', '/');
    }

    @Test
    void recordsWhatHappenedAndNoneOfTheValues(@TempDir Path dir) throws Exception {
        Path password = fixture();
        Path file = dir.resolve("seclume.jfr");

        try (Recording recording = new Recording()) {
            // Threshold to zero: the default of ten milliseconds makes this a
            // slow-query event, which is right in production and useless in a
            // test against a fast local server.
            recording.enable("space.seclume.Query").withThreshold(Duration.ZERO);
            recording.enable("space.seclume.ConnectionOpen");
            recording.start();

            try (Connection connection = DriverManager.getConnection(url(password));
                    Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists jfr_probe");
                statement.execute("create table jfr_probe (id int, note text)");
                statement.execute("insert into jfr_probe values (1, '" + SECRET + "')");
                try (ResultSet rows = statement.executeQuery(
                        "select id from jfr_probe where note = '" + SECRET + "'")) {
                    assertTrue(rows.next(), "the probe row should be there");
                }
                statement.execute("drop table if exists jfr_probe");
            }

            recording.stop();
            recording.dump(file);
        }

        List<RecordedEvent> events = RecordingFile.readAllEvents(file);

        // ---- it recorded something worth having -----------------------------
        List<RecordedEvent> connects = of(events, "space.seclume.ConnectionOpen");
        assertEquals(1, connects.size(), "one physical connection, one event");
        RecordedEvent connect = connects.get(0);
        assertEquals("postgresql", connect.getString("kind"));
        assertEquals(TestHosts.postgres() + ":" + TestHosts.postgresPort(),
                connect.getString("server"));
        assertEquals("seclume_test", connect.getString("database"));
        assertTrue(connect.getBoolean("succeeded"));

        List<RecordedEvent> queries = of(events, "space.seclume.Query");
        assertTrue(queries.size() >= 5,
                "five statements were run and " + queries.size() + " were recorded");

        RecordedEvent select = queries.stream()
                .filter(event -> event.getString("fingerprint").startsWith("select id"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("the select was not recorded; seen: "
                        + queries.stream().map(e -> e.getString("fingerprint")).toList()));
        assertEquals("select id from jfr_probe where note = ?", select.getString("fingerprint"));
        assertEquals(1, select.getLong("rows"));
        assertTrue(select.getLong("fingerprintId") != 0, "a fingerprint needs an id to group by");

        // ---- and none of it carries a value ---------------------------------
        List<String> leaked = new ArrayList<>();
        for (RecordedEvent event : events) {
            for (String text : everyString(event)) {
                if (text.toLowerCase(Locale.ROOT).contains(SECRET.toLowerCase(Locale.ROOT))) {
                    leaked.add(event.getEventType().getName() + ": " + text);
                }
            }
        }
        assertTrue(leaked.isEmpty(), () -> "a value reached the recording:\n  "
                + String.join("\n  ", leaked));
    }

    /**
     * The rest of the vocabulary, in one recording.
     *
     * <p>Separate from the case above because it needs TLS and a prepared
     * statement to make the remaining three events fire at all - and an
     * event class that nothing ever raises is worse than one that does not
     * exist, because it reads in the documentation as a feature.
     *
     * <p>The credential event is the one to look at twice. It says a secret
     * was fetched, from what kind of provider, how long that took and when it
     * expires. It does not say the secret, its length, or a hash of it: a
     * length is a fact about a password that an attacker is glad to have, and
     * this is the last place in the library that should hand one out.
     */
    @Test
    void recordsTheHandshakeTheCredentialAndTheCache(@TempDir Path dir) throws Exception {
        Path password = fixture();
        Path file = dir.resolve("seclume-tls.jfr");

        try (Recording recording = new Recording()) {
            recording.enable("space.seclume.TlsHandshake");
            recording.enable("space.seclume.CredentialRotation");
            recording.enable("space.seclume.StatementCache");
            recording.enable("space.seclume.Query").withThreshold(Duration.ZERO);
            recording.start();

            String url = url(password).replace("&tls=off", "&tls=require&tlsStack=seclume");
            try (Connection connection = DriverManager.getConnection(url)) {
                // Twice, so that the second lookup is a hit and the event has
                // both answers in the recording rather than only one.
                for (int round = 0; round < 2; round++) {
                    try (java.sql.PreparedStatement statement = connection.prepareStatement(
                            "select ? where ? = ?")) {
                        statement.setString(1, SECRET);
                        statement.setString(2, SECRET);
                        statement.setString(3, SECRET);
                        try (ResultSet rows = statement.executeQuery()) {
                            assertTrue(rows.next());
                        }
                    }
                }
            }
            recording.stop();
            recording.dump(file);
        }

        List<RecordedEvent> events = RecordingFile.readAllEvents(file);

        List<RecordedEvent> handshakes = of(events, "space.seclume.TlsHandshake");
        assertTrue(!handshakes.isEmpty(), "the handshake was not recorded");
        RecordedEvent handshake = handshakes.get(0);
        assertEquals("seclume", handshake.getString("stack"));
        assertTrue(handshake.getString("negotiated").startsWith("TLSv1.3"),
                handshake.getString("negotiated"));

        List<RecordedEvent> credentials = of(events, "space.seclume.CredentialRotation");
        assertTrue(!credentials.isEmpty(), "the credential fetch was not recorded");
        RecordedEvent credential = credentials.get(0);
        assertTrue(credential.getBoolean("succeeded"));
        assertEquals(-1, credential.getLong("expiresInSeconds"),
                "a file does not expire, and saying otherwise would be an invented number");

        List<RecordedEvent> cache = of(events, "space.seclume.StatementCache");
        assertTrue(cache.size() >= 2, "two lookups, " + cache.size() + " recorded");
        assertTrue(cache.stream().anyMatch(e -> e.getBoolean("hit")),
                "the second lookup should have found the plan");
        assertEquals("select ? where ? = ?", cache.get(0).getString("fingerprint"));

        // The same walk as above, over a different set of events - the
        // parameters here were bound rather than written into the text, which
        // is the case that would leak through a different route.
        List<String> leaked = new ArrayList<>();
        for (RecordedEvent event : events) {
            for (String text : everyString(event)) {
                if (text.toLowerCase(Locale.ROOT).contains(SECRET.toLowerCase(Locale.ROOT))) {
                    leaked.add(event.getEventType().getName() + ": " + text);
                }
            }
        }
        assertTrue(leaked.isEmpty(), () -> "a value reached the recording:" + NEWLINE_INDENT
                + String.join(NEWLINE_INDENT, leaked));
    }

    /**
     * Every string in an event, whatever its field is called.
     *
     * <p>Walking the fields rather than naming them is the whole point: a
     * field added later is the one nobody remembers to check, and this is the
     * check that has to survive that.
     */
    private static List<String> everyString(RecordedObject event) {
        List<String> found = new ArrayList<>();
        for (ValueDescriptor field : event.getFields()) {
            Object value = event.getValue(field.getName());
            if (value instanceof String text) {
                found.add(text);
            } else if (value instanceof RecordedObject nested) {
                found.addAll(everyString(nested));
            }
        }
        return found;
    }

    private static List<RecordedEvent> of(List<RecordedEvent> events, String name) {
        return events.stream().filter(e -> e.getEventType().getName().equals(name)).toList();
    }
}
