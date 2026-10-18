package space.seclume.mongodb.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
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
import java.util.concurrent.TimeUnit;

import org.bson.Document;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.mongodb.MongoOperationTimeoutException;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.cursor.TimeoutMode;
import com.mongodb.client.model.Filters;

import space.seclume.tck.TestHosts;

/** timeoutMS: one limit for the whole operation, and for a cursor its lifetime or each batch. */
@Timeout(120)
class LocalTimeoutTest {

    private static String url;

    @BeforeAll
    static void needsTheServer() {
        String host = System.getProperty("seclume.mongo.host", TestHosts.database());
        Path password = find(".local-mongo-password");
        Path ca = find(".local-mongo-ca.pem");
        assumeTrue(password != null && ca != null, "no MongoDB fixture files");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, 27017), 2000);
        } catch (IOException e) {
            assumeTrue(false, "no MongoDB on " + host + ":27017");
        }
        url = "mongodb://seclume_test@" + host + ":27017/?authSource=admin&provider=file&path="
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

    /** Each document takes the server {@code millis} to match. */
    private static Document slow(int millis) {
        return new Document("$where", "function() { sleep(" + millis + "); return true; }");
    }

    private MongoCollection<Document> some(MongoClient client, int documents) {
        MongoCollection<Document> things = client.getDatabase("seclume_test")
                .getCollection("zl_timeout_" + new ObjectId().toHexString());
        List<Document> many = new ArrayList<>();
        for (int i = 0; i < documents; i++) {
            many.add(new Document("_id", i));
        }
        things.insertMany(many);
        return things;
    }

    @Test
    void aSlowOperationEndsAtItsTimeout() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> things = some(client, 1);
            try {
                MongoCollection<Document> bounded = things.withTimeout(300, TimeUnit.MILLISECONDS);
                long start = System.nanoTime();
                assertTimeoutPreemptively(Duration.ofSeconds(5), () -> assertThrows(
                        MongoOperationTimeoutException.class,
                        () -> bounded.find(slow(3000)).first()));
                long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
                assertTrue(took < 2000, "the timeout of 300 ms took " + took + " ms");
                // Without one, the same client goes on.
                assertEquals(1, things.countDocuments());
            } finally {
                things.drop();
            }
        }
    }

    /**
     * CURSOR_LIFETIME: the whole iteration within the timeout - ten documents of
     * 200 ms each do not fit into 1 s. ITERATION: each batch has its own, and
     * one document per batch fits.
     */
    @Test
    void aCursorsLifetimeOrEachOfItsBatches() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> things = some(client, 10)
                    .withTimeout(1000, TimeUnit.MILLISECONDS);
            try {
                assertThrows(MongoOperationTimeoutException.class, () -> things.find(slow(200))
                        .batchSize(1).timeoutMode(TimeoutMode.CURSOR_LIFETIME)
                        .into(new ArrayList<>()));
                assertEquals(10, things.find(slow(200)).batchSize(1)
                        .timeoutMode(TimeoutMode.ITERATION).into(new ArrayList<>()).size());
            } finally {
                things.withTimeout(0, TimeUnit.MILLISECONDS).drop();
            }
        }
    }

    @Test
    void theUrlsTimeoutIsInheritedAndZeroMeansNone() {
        try (MongoClient client = SeclumeMongoClients.create(url + "&timeoutMS=1500")) {
            assertEquals(1500L, client.getTimeout(TimeUnit.MILLISECONDS));
            var db = client.getDatabase("seclume_test");
            assertEquals(1500L, db.getTimeout(TimeUnit.MILLISECONDS));
            MongoCollection<Document> things = some(client, 1);
            try {
                assertEquals(1500L, things.getTimeout(TimeUnit.MILLISECONDS));
                assertThrows(MongoOperationTimeoutException.class,
                        () -> things.find(slow(3000)).first());
                MongoCollection<Document> unbounded = things.withTimeout(0, TimeUnit.SECONDS);
                assertEquals(0, unbounded.find(slow(1700)).first().getInteger("_id"),
                        "timeoutMS=0 is no limit at all");
            } finally {
                things.drop();
            }
        }
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            assertNull(client.getTimeout(TimeUnit.MILLISECONDS));
        }
    }

    @Test
    void timeoutModeNeedsTimeoutMs() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> things = some(client, 1);
            try {
                assertThrows(IllegalArgumentException.class, () -> things.find()
                        .timeoutMode(TimeoutMode.ITERATION).first());
                assertEquals(1, things.find(Filters.eq("_id", 0)).into(new ArrayList<>()).size());
            } finally {
                things.drop();
            }
        }
    }
}
