package space.seclume.mongodb;

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
 * The official driver on seclume's socket, as a Flight Recorder recording
 * sees it: the connection, the SCRAM-SHA-256 login, and each command by its
 * shape - and a value planted in a document and a filter nowhere in any
 * field of any event.
 */
@Timeout(120)
// Alone: the recording takes the whole process's events.
@Isolated
class LocalOfficialDriverEventsTest {

    /** Letters only: a fingerprint lowercases and masks digits. */
    private static final String PLANTED = "plantedofficialdrivervalue";

    private static Path find(String name) {
        for (Path candidate : new Path[] {Path.of(name), Path.of("..", name)}) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    @Test
    void connectionLoginAndCommandsAreRecordedWithoutValues(@TempDir Path dir) throws Exception {
        String host = System.getProperty("seclume.mongo.host", TestHosts.database());
        Path password = find(".local-mongo-password");
        Path ca = find(".local-mongo-ca.pem");
        assumeTrue(password != null && ca != null, "no MongoDB fixture files");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, 27017), 2000);
        } catch (IOException e) {
            assumeTrue(false, "no MongoDB on " + host + ":27017");
        }
        String url = "mongodb://seclume_test@" + host + ":27017/?authSource=admin&provider=file"
                + "&path=" + password.toString().replace('\\', '/')
                + "&tlsRootCert=" + ca.toString().replace('\\', '/');
        String collection = "zl_official_" + new ObjectId().toHexString();
        Path file = dir.resolve("official.jfr");
        try (Recording recording = new Recording()) {
            recording.enable("space.seclume.Query").withThreshold(Duration.ZERO);
            recording.enable("space.seclume.ConnectionOpen");
            recording.enable("space.seclume.Authentication");
            recording.start();
            try (MongoClient client = SeclumeMongo.client(url)) {
                MongoCollection<Document> things = client.getDatabase("seclume_test")
                        .getCollection(collection);
                things.insertOne(new Document("code", PLANTED));
                things.find(Filters.eq("code", PLANTED)).first();
                things.drop();
            }
            recording.stop();
            recording.dump(file);
        }
        List<RecordedEvent> events = RecordingFile.readAllEvents(file);
        List<String> leaks = new ArrayList<>();
        List<String> shapes = new ArrayList<>();
        boolean login = false;
        boolean connected = false;
        for (RecordedEvent event : events) {
            String type = event.getEventType().getName();
            if (!type.startsWith("space.seclume.")) {
                continue;
            }
            search(event, type, leaks);
            switch (type) {
                case "space.seclume.Query" -> shapes.add(event.getString("fingerprint"));
                case "space.seclume.Authentication" -> login |= "SCRAM-SHA-256".equals(
                        event.getString("method")) && event.getBoolean("succeeded");
                case "space.seclume.ConnectionOpen" -> connected |= "mongodb".equals(
                        event.getString("kind")) && event.getBoolean("succeeded");
                default -> { }
            }
        }
        assertTrue(leaks.isEmpty(), "a value in the recording: " + leaks);
        assertTrue(login, "no login recorded");
        assertTrue(connected, "no connection recorded");
        assertTrue(shapes.stream().anyMatch(s -> s.startsWith("find seclume_test." + collection)
                && s.contains("filter {code: ?}")), "no find among " + shapes);
        assertTrue(shapes.stream().anyMatch(s -> s.startsWith("insert seclume_test."
                + collection)), "no insert among " + shapes);
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
