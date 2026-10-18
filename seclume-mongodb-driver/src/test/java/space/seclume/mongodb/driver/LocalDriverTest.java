package space.seclume.mongodb.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.bson.Document;
import org.bson.codecs.configuration.CodecRegistries;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.codecs.pojo.PojoCodecProvider;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.mongodb.MongoClientException;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCommandException;
import com.mongodb.ServerCursor;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.model.Filters;

import space.seclume.tck.TestHosts;

/** What the comparison with the official driver does not show by itself. */
@Timeout(180)
class LocalDriverTest {

    private static final int CURSOR_NOT_FOUND = 43;

    private static String url;

    @BeforeAll
    static void needsTheFixture() {
        String host = System.getProperty("seclume.mongo.host", TestHosts.database());
        int port = Integer.getInteger("seclume.mongo.port", 27017);
        Path password = find(".local-mongo-password");
        Path ca = find(".local-mongo-ca.pem");
        assumeTrue(password != null && ca != null, "no MongoDB fixture files");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException e) {
            assumeTrue(false, "no MongoDB on " + host + ":" + port);
        }
        url = "mongodb://seclume_test@" + host + ":" + port + "/?authSource=admin&provider=file"
                + "&path=" + password.toString().replace('\\', '/')
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

    private static String fresh() {
        return "zl_driver_" + new ObjectId().toHexString();
    }

    /** A cursor closed before its end is gone on the server, not left for its idle timeout. */
    @Test
    void aCursorClosedEarlyIsKilledOnTheServer() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> things = client.getDatabase("seclume_test")
                    .getCollection(fresh());
            try {
                List<Document> many = new ArrayList<>();
                for (int i = 0; i < 50; i++) {
                    many.add(new Document("_id", i));
                }
                things.insertMany(many);
                ServerCursor open;
                try (MongoCursor<Document> cursor = things.find().batchSize(5).cursor()) {
                    cursor.next();
                    open = cursor.getServerCursor();
                    assertNotNull(open, "five of fifty read: the cursor is open on the server");
                }
                MongoCommandException gone = assertThrows(MongoCommandException.class,
                        () -> client.getDatabase("seclume_test").runCommand(
                                new Document("getMore", open.getId())
                                        .append("collection", things.getNamespace()
                                                .getCollectionName())));
                assertEquals(CURSOR_NOT_FOUND, gone.getErrorCode(), gone.getMessage());
            } finally {
                things.drop();
            }
        }
    }

    /** {@code first} asks for one document in one batch: no cursor stays behind. */
    @Test
    void firstLeavesNoCursor() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> things = client.getDatabase("seclume_test")
                    .getCollection(fresh());
            try {
                things.insertMany(List.of(new Document("_id", 1), new Document("_id", 2)));
                try (MongoCursor<Document> cursor = ((Iterables.Find<Document>) things.find())
                        .firstOnly()) {
                    assertNull(cursor.getServerCursor());
                }
                assertEquals(1, things.find().first().getInteger("_id"));
            } finally {
                things.drop();
            }
        }
    }

    public record Point(String name, int x, int y) {
    }

    /** The application's codecs: a record through the POJO codec, ids made for it by the server. */
    @Test
    void theApplicationsCodecsAreUsed() {
        CodecRegistry codecs = CodecRegistries.fromRegistries(
                MongoClientSettings.getDefaultCodecRegistry(),
                CodecRegistries.fromProviders(PojoCodecProvider.builder().automatic(true).build()));
        try (MongoClient client = SeclumeMongoClients.create(url, codecs)) {
            MongoCollection<Point> points = client.getDatabase("seclume_test")
                    .getCollection(fresh(), Point.class);
            try {
                points.insertMany(List.of(new Point("a", 1, 2), new Point("b", 3, 4)));
                assertEquals(new Point("b", 3, 4), points.find(Filters.eq("name", "b")).first());
                assertEquals(List.of("a", "b"), points.distinct("name", String.class)
                        .into(new ArrayList<>()));
                Document raw = points.withDocumentClass(Document.class).find().first();
                assertTrue(raw.get("_id") instanceof ObjectId, raw.toJson());
            } finally {
                points.drop();
            }
        }
    }

    /** More threads than connections: they wait their turn, and every write arrives. */
    @Test
    void manyThreadsShareAFewConnections() throws Exception {
        try (MongoClient client = SeclumeMongoClients.create(url + "&maxPoolSize=3")) {
            MongoCollection<Document> things = client.getDatabase("seclume_test")
                    .getCollection(fresh());
            ExecutorService threads = Executors.newFixedThreadPool(12);
            try {
                List<Future<?>> done = new ArrayList<>();
                for (int t = 0; t < 12; t++) {
                    int thread = t;
                    done.add(threads.submit(() -> {
                        for (int i = 0; i < 40; i++) {
                            things.insertOne(new Document("t", thread).append("i", i));
                            things.find(Filters.eq("t", thread)).first();
                        }
                    }));
                }
                for (Future<?> one : done) {
                    one.get();
                }
                assertEquals(12 * 40, things.countDocuments());
            } finally {
                threads.shutdownNow();
                things.drop();
            }
        }
    }

    /** What is not there yet says so, instead of doing something else. */
    @Test
    void whatIsNotSupportedYetSaysSo() {
        assertThrows(MongoClientException.class, () -> SeclumeMongoClients.create(
                url.replace("mongodb://", "mongodb+srv://").replaceAll(":[0-9]+/", "/")));
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            UnsupportedOperationException unacknowledged = assertThrows(
                    UnsupportedOperationException.class, () -> client.getDatabase("seclume_test")
                            .getCollection(fresh())
                            .withWriteConcern(com.mongodb.WriteConcern.UNACKNOWLEDGED)
                            .insertOne(new Document()));
            assertTrue(unacknowledged.getMessage().contains("w: 0"));
        }
    }
}
