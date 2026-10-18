package space.seclume.mongodb.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
import java.util.concurrent.TimeUnit;

import org.bson.BsonDocument;
import org.bson.BsonTimestamp;
import org.bson.Document;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.mongodb.MongoChangeStreamException;
import com.mongodb.client.MongoChangeStreamCursor;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Aggregates;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Projections;
import com.mongodb.client.model.Updates;
import com.mongodb.client.model.changestream.ChangeStreamDocument;
import com.mongodb.client.model.changestream.FullDocument;
import com.mongodb.client.model.changestream.OperationType;

import space.seclume.tck.TestHosts;

/** Change streams against the replica set fixture. */
@Timeout(180)
class LocalChangeStreamTest {

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

    private static MongoCollection<Document> fresh(MongoClient client) {
        MongoCollection<Document> things = client.getDatabase("seclume_test")
                .getCollection("zl_stream_" + new ObjectId().toHexString());
        things.insertOne(new Document("_id", "seed"));         // the collection exists
        return things;
    }

    /** The next event, waited for up to ten seconds. */
    private static <T> T next(MongoChangeStreamCursor<T> cursor) {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < until) {
            T event = cursor.tryNext();
            if (event != null) {
                return event;
            }
        }
        throw new AssertionError("no event within ten seconds");
    }

    @Test
    void insertsUpdatesAndDeletesAsTheyHappen() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> things = fresh(client);
            try (MongoChangeStreamCursor<ChangeStreamDocument<Document>> stream = things.watch()
                    .fullDocument(FullDocument.UPDATE_LOOKUP)
                    .maxAwaitTime(200, TimeUnit.MILLISECONDS).cursor()) {
                things.insertOne(new Document("_id", 1).append("v", "one"));
                things.updateOne(Filters.eq("_id", 1), Updates.set("v", "uno"));
                ChangeStreamDocument<Document> insert = next(stream);
                assertEquals(OperationType.INSERT, insert.getOperationType());
                assertEquals("one", insert.getFullDocument().getString("v"));
                ChangeStreamDocument<Document> update = next(stream);
                assertEquals(OperationType.UPDATE, update.getOperationType());
                assertEquals("uno", update.getFullDocument().getString("v"),
                        "UPDATE_LOOKUP did not bring the document");
                assertEquals("uno", update.getUpdateDescription().getUpdatedFields()
                        .getString("v").getValue());
                // Deleted only now: UPDATE_LOOKUP reads the document when the event is read.
                things.deleteOne(Filters.eq("_id", 1));
                assertEquals(OperationType.DELETE, next(stream).getOperationType());
                assertNull(stream.tryNext(), "an event out of nothing");
                assertNotNull(stream.getResumeToken());
            } finally {
                things.drop();
            }
        }
    }

    /**
     * The connection under the stream breaks on a getMore: the stream opens
     * again from its resume token, and every event comes once.
     */
    @Test
    void aBrokenStreamResumesWithoutLosingOrRepeating() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> things = fresh(client);
            try (MongoChangeStreamCursor<ChangeStreamDocument<Document>> stream = things.watch()
                    .maxAwaitTime(200, TimeUnit.MILLISECONDS).cursor()) {
                things.insertOne(new Document("_id", "a"));
                assertEquals("a", next(stream).getDocumentKey().getString("_id").getValue());
                long before = stream.getServerCursor().getId();
                client.getDatabase("admin").runCommand(new Document("configureFailPoint",
                        "failCommand").append("mode", new Document("times", 1))
                        .append("data", new Document("failCommands", List.of("getMore"))
                                .append("closeConnection", true)));
                things.insertMany(List.of(new Document("_id", "b"), new Document("_id", "c")));
                List<String> keys = new ArrayList<>();
                keys.add(next(stream).getDocumentKey().getString("_id").getValue());
                keys.add(next(stream).getDocumentKey().getString("_id").getValue());
                assertEquals(List.of("b", "c"), keys);
                assertNotEquals(before, stream.getServerCursor().getId(),
                        "the stream was not opened again - the fail point did not hit it");
                things.insertOne(new Document("_id", "d"));
                assertEquals("d", next(stream).getDocumentKey().getString("_id").getValue());
            } finally {
                client.getDatabase("admin").runCommand(new Document("configureFailPoint",
                        "failCommand").append("mode", "off"));
                things.drop();
            }
        }
    }

    @Test
    void resumeAfterAndStartAtOperationTime() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> things = fresh(client);
            try {
                BsonDocument afterFirst;
                BsonTimestamp beforeAll;
                try (MongoChangeStreamCursor<ChangeStreamDocument<Document>> stream = things
                        .watch().maxAwaitTime(200, TimeUnit.MILLISECONDS).cursor()) {
                    things.insertOne(new Document("_id", 1));
                    ChangeStreamDocument<Document> first = next(stream);
                    beforeAll = first.getClusterTime();
                    afterFirst = first.getResumeToken();
                    things.insertOne(new Document("_id", 2));
                    next(stream);
                }
                try (MongoChangeStreamCursor<ChangeStreamDocument<Document>> resumed = things
                        .watch().resumeAfter(afterFirst)
                        .maxAwaitTime(200, TimeUnit.MILLISECONDS).cursor()) {
                    assertEquals(2, next(resumed).getDocumentKey().getInt32("_id").getValue());
                }
                try (MongoChangeStreamCursor<ChangeStreamDocument<Document>> fromTime = things
                        .watch().startAtOperationTime(beforeAll)
                        .maxAwaitTime(200, TimeUnit.MILLISECONDS).cursor()) {
                    assertEquals(1, next(fromTime).getDocumentKey().getInt32("_id").getValue());
                    assertEquals(2, next(fromTime).getDocumentKey().getInt32("_id").getValue());
                }
            } finally {
                things.drop();
            }
        }
    }

    @Test
    void aDatabaseAndTheClusterSeeTheCollection() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> things = fresh(client);
            try (var onDatabase = client.getDatabase("seclume_test").watch(List.of(
                         Aggregates.match(Filters.eq("ns.coll",
                                 things.getNamespace().getCollectionName()))))
                    .maxAwaitTime(200, TimeUnit.MILLISECONDS).cursor();
                 var onCluster = client.watch(List.of(Aggregates.match(Filters.eq("ns.coll",
                         things.getNamespace().getCollectionName()))))
                         .maxAwaitTime(200, TimeUnit.MILLISECONDS).cursor()) {
                things.insertOne(new Document("_id", "x"));
                assertEquals("x", next(onDatabase).getDocumentKey().getString("_id").getValue());
                assertEquals("x", next(onCluster).getDocumentKey().getString("_id").getValue());
            } finally {
                things.drop();
            }
        }
    }

    /**
     * A pipeline that removes the resume token is refused - by the client
     * (MongoChangeStreamException) on a server that lets it through, and by
     * MongoDB 8 itself (ChangeStreamFatalError, 280) before that.
     */
    @Test
    void anEventWithoutItsTokenIsRefused() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> things = fresh(client);
            try (var stream = things.watch(List.of(Aggregates.project(Projections.excludeId())))
                    .withDocumentClass(Document.class).cursor()) {
                things.insertOne(new Document("_id", 1));
                RuntimeException refused = assertThrows(RuntimeException.class, () -> {
                    long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                    while (System.nanoTime() < until) {
                        stream.tryNext();
                    }
                });
                boolean byClient = refused instanceof MongoChangeStreamException;
                boolean byServer = refused instanceof com.mongodb.MongoCommandException command
                        && command.getErrorCode() == 280;
                assertTrue(byClient || byServer, refused.toString());
            } finally {
                things.drop();
            }
        }
    }
}
