package space.seclume.mongodb.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.bson.Document;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;

import jdk.jfr.Recording;
import jdk.jfr.ValueDescriptor;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedObject;
import jdk.jfr.consumer.RecordingFile;

import space.seclume.tck.TestHosts;

/**
 * seclume's Flight Recorder events from the MongoDB driver, against the
 * replica set: the connection, the login, each command by its shape, and a
 * retry on another connection as a failover - and nowhere in any of them a
 * value the application wrote or asked for.
 *
 * <p>As {@code JfrNoValuesTest} does for the SQL drivers, a value is planted
 * in a document and in a filter, and every field of every recorded event is
 * searched for it: the fields added later are the ones nobody thinks to check.
 */
@Timeout(180)
// Alone: the recording takes the whole process's events.
@Isolated
class LocalMongoEventsTest {

    /**
     * Letters only, searched for in any case: a fingerprint lowercases and
     * masks digits, and a value with digits would come out changed - and
     * slip past a search for it as it was.
     */
    private static final String PLANTED = "hunterswordfishjfrmongoplanted";
    private static String url;

    @BeforeAll
    static void needsTheReplicaSet() {
        String host = System.getProperty("seclume.mongo.host", TestHosts.database());
        Path password = find(".local-mongo-password");
        Path ca = find(".local-mongo-rs-ca.pem");
        assumeTrue(password != null && ca != null, "no replica set fixture files");
        for (int port = 27021; port <= 27023; port++) {
            try (Socket probe = new Socket()) {
                probe.connect(new InetSocketAddress(host, port), 2000);
            } catch (IOException e) {
                assumeTrue(false, "no replica set member on " + host + ":" + port);
            }
        }
        url = "mongodb://seclume_test@" + host + ":27021," + host + ":27022," + host
                + ":27023/?replicaSet=slm-rs&authSource=admin&provider=file&path="
                + password.toString().replace('\\', '/')
                + "&tlsRootCert=" + ca.toString().replace('\\', '/');
    }

    private static Path find(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    @Test
    void theEventsSayWhatHappenedAndNoValue(@TempDir Path directory) throws Exception {
        Path file = directory.resolve("seclume-mongodb.jfr");
        String collection = "zl_events_" + new ObjectId().toHexString();
        try (Recording recording = new Recording()) {
            recording.enable("space.seclume.Query").withThreshold(Duration.ZERO);
            recording.enable("space.seclume.ConnectionOpen");
            recording.enable("space.seclume.Authentication");
            recording.enable("space.seclume.TlsHandshake");
            recording.enable("space.seclume.Failover");
            recording.start();
            try (MongoClient client = SeclumeMongoClients.create(url)) {
                MongoCollection<Document> things = client.getDatabase("seclume_test")
                        .getCollection(collection);
                try {
                    things.insertOne(new Document("_id", 1).append("code", PLANTED)
                            .append("tags", List.of(PLANTED)));
                    assertEquals(1, things.countDocuments(Filters.and(Filters.eq("code",
                            PLANTED), Filters.in("tags", PLANTED))));
                    things.find(Filters.eq("code", PLANTED)).first();
                    // A read that fails once on its connection and goes again.
                    client.getDatabase("admin").runCommand(new Document("configureFailPoint",
                            "failCommand").append("mode", new Document("times", 1))
                            .append("data", new Document("failCommands", List.of("find"))
                                    .append("closeConnection", true)));
                    things.find(Filters.eq("code", PLANTED)).first();
                } finally {
                    client.getDatabase("admin").runCommand(new Document("configureFailPoint",
                            "failCommand").append("mode", "off"));
                    things.drop();
                }
            }
            recording.stop();
            recording.dump(file);
        }

        List<RecordedEvent> events = RecordingFile.readAllEvents(file);
        List<String> leaks = new ArrayList<>();
        for (RecordedEvent event : events) {
            if (event.getEventType().getName().startsWith("space.seclume.")) {
                search(event, event.getEventType().getName(), leaks);
            }
        }
        assertTrue(leaks.isEmpty(), "a value in the recording: " + leaks);

        List<String> shapes = strings(events, "space.seclume.Query", "fingerprint");
        assertTrue(shapes.stream().anyMatch(s -> s.startsWith("insert seclume_test."
                + collection)), "no insert among " + shapes);
        assertTrue(shapes.stream().anyMatch(s -> s.startsWith("find seclume_test."
                + collection) && s.contains("filter {code: ?}")), "no find among " + shapes);
        assertTrue(shapes.stream().anyMatch(s -> s.startsWith("aggregate seclume_test."
                + collection) && s.contains("tags: {$in: ?}")),
                "no count's pipeline among " + shapes);
        assertFalse(shapes.stream().anyMatch(s -> s.startsWith("hello")),
                "the monitor's hello recorded as a query");
        assertTrue(strings(events, "space.seclume.Query", "kind").stream()
                .allMatch("mongodb"::equals));

        assertTrue(strings(events, "space.seclume.Authentication", "method")
                .contains("SCRAM-SHA-256"), "no login recorded");
        assertTrue(events.stream().anyMatch(e -> e.getEventType().getName()
                .equals("space.seclume.ConnectionOpen") && e.getBoolean("succeeded")
                && "mongodb".equals(e.getString("kind"))), "no connection recorded");
        List<String> reasons = strings(events, "space.seclume.Failover", "reason");
        assertTrue(reasons.stream().anyMatch(r -> r.startsWith("retried after")),
                "the retried read is no failover event: " + reasons);
    }

    private static List<String> strings(List<RecordedEvent> events, String type, String field) {
        List<String> out = new ArrayList<>();
        for (RecordedEvent event : events) {
            if (event.getEventType().getName().equals(type)) {
                Object value = event.getValue(field);
                out.add(String.valueOf(value));
            }
        }
        return out;
    }

    private static void search(RecordedObject object, String where, List<String> leaks) {
        for (ValueDescriptor field : object.getFields()) {
            Object value = object.getValue(field.getName());
            if (value instanceof RecordedObject nested) {
                search(nested, where + "." + field.getName(), leaks);
            } else if (value != null && String.valueOf(value).toLowerCase(Locale.ROOT)
                    .contains(PLANTED)) {
                leaks.add(where + "." + field.getName());
            }
        }
    }
}
