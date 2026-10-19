package space.seclume.mongodb.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
import java.util.concurrent.atomic.AtomicInteger;

import org.bson.Document;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.mongodb.ClientSessionOptions;
import com.mongodb.MongoException;
import com.mongodb.MongoSocketException;
import com.mongodb.ReadConcern;
import com.mongodb.ReadPreference;
import com.mongodb.TransactionOptions;
import com.mongodb.WriteConcern;
import com.mongodb.client.ClientSession;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Updates;
import com.mongodb.connection.ClusterType;
import com.mongodb.connection.ServerType;

import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/**
 * Against a replica set of three (the {@code slm-rs} fixture): discovery,
 * reads from secondaries, causal consistency, transactions, retryable writes
 * and a primary that steps down. Skipped without the fixture.
 */
@Timeout(300)
class LocalReplicaSetTest {

    private static String host;
    private static Path passwordFile;
    private static String options;

    @BeforeAll
    static void needsTheReplicaSet() {
        host = System.getProperty("seclume.mongo.host", TestHosts.database());
        passwordFile = find(".local-mongo-password");
        Path ca = find(".local-mongo-rs-ca.pem");
        assumeTrue(passwordFile != null && ca != null, "no replica set fixture files");
        for (int port = 27021; port <= 27023; port++) {
            try (Socket probe = new Socket()) {
                probe.connect(new InetSocketAddress(host, port), 2000);
            } catch (IOException e) {
                assumeTrue(false, "no replica set member on " + host + ":" + port);
            }
        }
        options = "authSource=admin&provider=file&path="
                + passwordFile.toString().replace('\\', '/')
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

    private static MongoClient client(String hosts, String more) {
        return SeclumeMongoClients.create("mongodb://seclume_test@" + hosts
                + "/?replicaSet=slm-rs&" + options + more);
    }

    private static MongoClient all(String more) {
        return client(host + ":27021," + host + ":27022," + host + ":27023", more);
    }

    private static MongoCollection<Document> fresh(MongoClient client) {
        return client.getDatabase("seclume_test").getCollection("zl_rs_"
                + new ObjectId().toHexString());
    }

    @Test
    void theWholeSetIsFoundFromOneSecondary() throws Exception {
        try (MongoClient client = client(host + ":27023", "")) {
            MongoCollection<Document> things = fresh(client);
            try {
                things.insertOne(new Document("_id", 1));          // needs the primary
                var description = client.getClusterDescription();
                assertEquals(ClusterType.REPLICA_SET, description.getType());
                assertEquals(3, description.getServerDescriptions().size(),
                        description.getShortDescription());
                assertEquals(1, description.getServerDescriptions().stream()
                        .filter(s -> s.getType() == ServerType.REPLICA_SET_PRIMARY).count());
                assertEquals(2, description.getServerDescriptions().stream()
                        .filter(s -> s.getType() == ServerType.REPLICA_SET_SECONDARY).count());
            } finally {
                things.drop();
            }
        }
        NoSecretInHeap.assertAbsent(passwordFile);
    }

    /** A read for a secondary goes to one, and a causally consistent session sees its own write there. */
    @Test
    void aSecondaryReadsWhatTheSessionWrote() {
        try (MongoClient client = all("")) {
            MongoCollection<Document> things = fresh(client);
            try {
                things.insertOne(new Document("_id", 0));
                try (ClientSession session = client.startSession(ClientSessionOptions.builder()
                        .causallyConsistent(true).build())) {
                    for (int i = 1; i <= 20; i++) {
                        things.withWriteConcern(WriteConcern.W1)
                                .insertOne(session, new Document("_id", i));
                        MongoCollection<Document> fromSecondary = things
                                .withReadPreference(ReadPreference.secondary())
                                .withReadConcern(ReadConcern.MAJORITY);
                        Document seen = fromSecondary.find(session, Filters.eq("_id", i)).first();
                        assertEquals(i, seen == null ? -1 : seen.getInteger("_id"),
                                "the secondary did not wait for the session's write " + i);
                    }
                }
                try (MongoCursor<Document> cursor = things
                        .withReadPreference(ReadPreference.secondary()).find().batchSize(2)
                        .cursor()) {
                    cursor.next();
                    String primary = client.getClusterDescription().getServerDescriptions()
                            .stream().filter(s -> s.getType() == ServerType.REPLICA_SET_PRIMARY)
                            .findFirst().orElseThrow().getAddress().toString();
                    assertNotEquals(primary, cursor.getServerAddress().toString());
                }
            } finally {
                things.drop();
            }
        }
    }

    @Test
    void aCommittedTransactionIsSeenAndAnAbortedOneIsNot() {
        try (MongoClient client = all("")) {
            MongoCollection<Document> things = fresh(client);
            try {
                things.insertOne(new Document("_id", "seed"));   // creates the collection
                try (ClientSession session = client.startSession()) {
                    session.startTransaction();
                    things.insertOne(session, new Document("_id", "a"));
                    things.updateOne(session, Filters.eq("_id", "seed"), Updates.set("v", 1));
                    assertEquals(2, things.countDocuments(session), "the transaction sees itself");
                    assertEquals(1, things.countDocuments(), "outside, nothing is visible yet");
                    session.commitTransaction();
                    assertEquals(2, things.countDocuments());
                    assertEquals(1, things.find(Filters.eq("_id", "seed")).first().getInteger("v"));

                    session.startTransaction();
                    things.insertOne(session, new Document("_id", "b"));
                    things.deleteOne(session, Filters.eq("_id", "a"));
                    session.abortTransaction();
                    assertEquals(2, things.countDocuments());
                    assertNull(things.find(Filters.eq("_id", "b")).first());
                }
                // A session closed with a transaction open aborts it.
                try (ClientSession session = client.startSession()) {
                    session.startTransaction();
                    things.insertOne(session, new Document("_id", "c"));
                }
                assertNull(things.find(Filters.eq("_id", "c")).first());
            } finally {
                things.drop();
            }
        }
    }

    /** A snapshot session reads as of its first read; a write after that is not in it. */
    @Test
    void aSnapshotSessionReadsAsOfItsFirstRead() {
        try (MongoClient client = all("")) {
            MongoCollection<Document> things = fresh(client).withWriteConcern(WriteConcern.MAJORITY);
            try {
                things.insertOne(new Document("_id", 1));
                try (ClientSession snapshot = client.startSession(ClientSessionOptions.builder()
                        .snapshot(true).build())) {
                    assertEquals(1, things.find(snapshot).into(new ArrayList<>()).size());
                    assertTrue(snapshot.getSnapshotTimestamp() != null,
                            "the first read did not fix the point in time");
                    things.insertOne(new Document("_id", 2));
                    assertEquals(1, things.find(snapshot).into(new ArrayList<>()).size(),
                            "a write after the snapshot is in it");
                    assertEquals(List.of(1), things.distinct(snapshot, "_id", Integer.class)
                            .into(new ArrayList<>()));
                    assertThrows(IllegalStateException.class, snapshot::startTransaction);
                }
                try (ClientSession later = client.startSession(ClientSessionOptions.builder()
                        .snapshot(true).build())) {
                    assertEquals(2, things.find(later).into(new ArrayList<>()).size());
                }
            } finally {
                things.drop();
            }
        }
    }

    /** withTransaction runs the body again after a transient error - here a write conflict. */
    @Test
    void withTransactionRetriesAWriteConflict() throws Exception {
        try (MongoClient client = all("")) {
            MongoCollection<Document> things = fresh(client);
            try {
                things.insertOne(new Document("_id", 1).append("n", 0));
                AtomicInteger attempts = new AtomicInteger();
                try (ClientSession session = client.startSession();
                     ClientSession other = client.startSession()) {
                    int result = session.withTransaction(() -> {
                        things.updateOne(session, Filters.eq("_id", 1), Updates.inc("n", 1));
                        if (attempts.incrementAndGet() == 1) {
                            // Another transaction writes the same document and commits:
                            // ours is now in conflict and gets a transient error.
                            other.startTransaction();
                            MongoException conflict = assertThrows(MongoException.class,
                                    () -> things.updateOne(other, Filters.eq("_id", 1),
                                            Updates.inc("n", 100)));
                            assertTrue(conflict.hasErrorLabel(
                                    MongoException.TRANSIENT_TRANSACTION_ERROR_LABEL),
                                    conflict.toString());
                            other.abortTransaction();
                            throw conflict;
                        }
                        return attempts.get();
                    }, TransactionOptions.builder().writeConcern(WriteConcern.MAJORITY).build());
                    assertEquals(2, result);
                }
                assertEquals(1, things.find().first().getInteger("n"));
            } finally {
                things.drop();
            }
        }
    }

    /**
     * The server drops the connection after it applied an insert: the retry
     * goes with the same transaction number, and the document is there once.
     * Without retryWrites the same failure reaches the application.
     */
    @Test
    void aWriteIsRetriedOnceAndAppliedOnce() {
        try (MongoClient client = all("")) {
            MongoCollection<Document> things = fresh(client);
            try {
                things.insertOne(new Document("_id", "first"));
                failNext(client, "insert", 1);
                things.insertOne(new Document("_id", "retried"));
                assertEquals(1, things.countDocuments(Filters.eq("_id", "retried")));
                failNext(client, "update", 1);
                things.updateOne(Filters.eq("_id", "retried"), Updates.inc("n", 1));
                assertEquals(1, things.find(Filters.eq("_id", "retried")).first()
                        .getInteger("n"), "the retried $inc ran twice");
            } finally {
                off(client);
                things.drop();
            }
        }
        try (MongoClient client = all("&retryWrites=false")) {
            MongoCollection<Document> things = fresh(client);
            try {
                things.insertOne(new Document("_id", "first"));
                failNext(client, "insert", 1);
                assertThrows(MongoSocketException.class,
                        () -> things.insertOne(new Document("_id", "not retried")));
            } finally {
                off(client);
                things.drop();
            }
        }
    }

    /**
     * A refusal the server labels RetryableWriteError - here ShutdownInProgress
     * - is retried as well, not only a dropped connection. The label is in the
     * reply; found missing on the exception during the step-down test.
     */
    @Test
    void aRefusalLabelledRetryableIsRetried() {
        try (MongoClient client = all("")) {
            MongoCollection<Document> things = fresh(client);
            try {
                things.insertOne(new Document("_id", "first"));
                client.getDatabase("admin").runCommand(new Document("configureFailPoint",
                        "failCommand").append("mode", new Document("times", 1))
                        .append("data", new Document("failCommands", List.of("insert"))
                                .append("errorCode", 91)
                                .append("errorLabels", List.of("RetryableWriteError"))));
                things.insertOne(new Document("_id", "retried"));
                assertEquals(1, things.countDocuments(Filters.eq("_id", "retried")));
            } finally {
                off(client);
                things.drop();
            }
        }
    }

    private static void failNext(MongoClient client, String command, int times) {
        client.getDatabase("admin").runCommand(new Document("configureFailPoint", "failCommand")
                .append("mode", new Document("times", times))
                .append("data", new Document("failCommands", List.of(command))
                        .append("closeConnection", true)));
    }

    private static void off(MongoClient client) {
        client.getDatabase("admin").runCommand(new Document("configureFailPoint", "failCommand")
                .append("mode", "off"));
    }

    /** The primary steps down; writes go on once the set has elected the next one. */
    @Test
    void writesGoOnAfterThePrimaryStepsDown() throws Exception {
        try (MongoClient client = all("&serverSelectionTimeoutMS=60000&heartbeatFrequencyMS=1000")) {
            MongoCollection<Document> things = fresh(client);
            try {
                things.insertOne(new Document("_id", 0));
                String before = primaryOf(client);
                try {
                    client.getDatabase("admin").runCommand(new Document("replSetStepDown", 10)
                            .append("secondaryCatchUpPeriodSecs", 5));
                } catch (MongoException closedOnUs) {
                    // the stepping-down primary closes connections; that is the point
                }
                List<Integer> written = new ArrayList<>();
                long until = System.nanoTime() + Duration.ofSeconds(45).toNanos();
                for (int i = 1; i <= 30 && System.nanoTime() < until; i++) {
                    things.insertOne(new Document("_id", i));
                    written.add(i);
                }
                assertEquals(30, written.size());
                assertEquals(31, things.countDocuments());
                assertNotEquals(before, primaryOf(client), "no other primary was elected");
            } finally {
                things.drop();
            }
        }
        // Give the preferred member its role back for the next run.
        try (MongoClient client = all("&serverSelectionTimeoutMS=60000")) {
            long until = System.nanoTime() + Duration.ofSeconds(60).toNanos();
            while (!primaryOf(client).endsWith(":27021") && System.nanoTime() < until) {
                Thread.sleep(1000);
            }
        }
    }

    private static String primaryOf(MongoClient client) {
        fresh(client).find().first();                 // let the monitor look at least once
        return client.getClusterDescription().getServerDescriptions().stream()
                .filter(s -> s.getType() == ServerType.REPLICA_SET_PRIMARY).findFirst()
                .map(s -> s.getAddress().toString()).orElse("none");
    }
}
