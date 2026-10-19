package space.seclume.mongodb.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.bson.Document;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.mongodb.ClientSessionOptions;
import com.mongodb.ReadConcern;
import com.mongodb.TransactionOptions;
import com.mongodb.WriteConcern;
import com.mongodb.client.ClientSession;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;

import space.seclume.tck.TestHosts;

/** A session handed off by one client and carried on by another, against the replica set. */
@Timeout(180)
class LocalSessionHandOffTest {

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
    void aTransactionIsCommittedByTheClientThatTookItUp() {
        try (MongoClient here = SeclumeMongoClients.create(url);
             MongoClient there = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> things = here.getDatabase("seclume_test")
                    .getCollection("zl_handoff_" + new ObjectId().toHexString());
            things.insertOne(new Document("_id", "seed"));
            try {
                ClientSession session = here.startSession();
                session.startTransaction(TransactionOptions.builder()
                        .readConcern(ReadConcern.SNAPSHOT).writeConcern(WriteConcern.MAJORITY)
                        .build());
                things.insertOne(session, new Document("_id", 1));
                byte[] state = SeclumeSessions.handOff(session);
                assertThrows(IllegalStateException.class,
                        () -> things.insertOne(session, new Document("_id", 9)),
                        "the session that was let go of still works");
                assertEquals(1, things.countDocuments(), "the transaction is visible early");

                MongoCollection<Document> same = there.getDatabase("seclume_test")
                        .getCollection(things.getNamespace().getCollectionName());
                ClientSession carried = SeclumeSessions.takeUp(there, state);
                assertTrue(carried.hasActiveTransaction());
                assertEquals(WriteConcern.MAJORITY,
                        carried.getTransactionOptions().getWriteConcern());
                assertEquals(2, same.countDocuments(carried), "the transaction sees A's write");
                same.insertOne(carried, new Document("_id", 2));
                carried.commitTransaction();
                carried.close();
                assertEquals(3, things.countDocuments());
            } finally {
                things.drop();
            }
        }
    }

    @Test
    void aTransactionTakenUpCanBeAborted() {
        try (MongoClient here = SeclumeMongoClients.create(url);
             MongoClient there = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> things = here.getDatabase("seclume_test")
                    .getCollection("zl_handoff_" + new ObjectId().toHexString());
            things.insertOne(new Document("_id", "seed"));
            try {
                ClientSession session = here.startSession();
                session.startTransaction();
                things.insertOne(session, new Document("_id", 1));
                try (ClientSession carried = SeclumeSessions.takeUp(there,
                        SeclumeSessions.handOff(session))) {
                    carried.abortTransaction();
                    assertFalse(carried.hasActiveTransaction());
                }
                assertEquals(1, things.countDocuments(), "the aborted write is there");
            } finally {
                things.drop();
            }
        }
    }

    @Test
    void whatCannotBeHandedOff() {
        try (MongoClient here = SeclumeMongoClients.create(url);
             MongoClient official = MongoClients.create("mongodb://127.0.0.1:1")) {
            ClientSession snapshot = here.startSession(ClientSessionOptions.builder()
                    .snapshot(true).build());
            assertThrows(IllegalStateException.class, () -> SeclumeSessions.handOff(snapshot));
            snapshot.close();
            ClientSession closed = here.startSession();
            closed.close();
            assertThrows(IllegalStateException.class, () -> SeclumeSessions.handOff(closed));
            byte[] state = SeclumeSessions.handOff(here.startSession());
            assertThrows(IllegalArgumentException.class,
                    () -> SeclumeSessions.takeUp(official, state));
            assertThrows(IllegalArgumentException.class,
                    () -> SeclumeSessions.takeUp(here, new byte[] {9, 0, 0, 0, 0}));
            byte[] cut = java.util.Arrays.copyOf(state, state.length - 3);
            assertThrows(IllegalArgumentException.class, () -> SeclumeSessions.takeUp(here, cut));
        }
    }
}
