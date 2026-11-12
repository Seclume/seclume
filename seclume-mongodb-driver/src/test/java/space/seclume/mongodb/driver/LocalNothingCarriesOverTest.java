package space.seclume.mongodb.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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

import org.bson.Document;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.mongodb.client.ClientSession;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;

import space.seclume.tck.TestHosts;

/**
 * Nothing one borrower does reaches the next: not a login of its own on a
 * pooled connection, not a cursor it left open in a session, not a
 * transaction - and a connection idle too long is not lent again.
 */
@Timeout(120)
class LocalNothingCarriesOverTest {

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

    @Test
    void aPooledConnectionIsNotLoggedInAgainOrOut() {
        try (MongoClient client = SeclumeMongoClients.create(url + "&maxPoolSize=1")) {
            var admin = client.getDatabase("admin");
            for (Document refused : List.of(new Document("logout", 1),
                    new Document("saslStart", 1).append("mechanism", "SCRAM-SHA-256"),
                    new Document("authenticate", 1).append("mechanism", "MONGODB-X509"))) {
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                        () -> admin.runCommand(refused));
                assertTrue(e.getMessage().contains("logged in by seclume"), e.getMessage());
            }
            Document status = admin.runCommand(new Document("connectionStatus", 1));
            assertEquals(1, status.get("authInfo", Document.class)
                    .getList("authenticatedUsers", Document.class).size());
        }
    }

    /** A cursor left open in a session is killed on the server when the session ends. */
    @Test
    void aCursorLeftOpenEndsWithItsSession() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> things = client.getDatabase("seclume_test")
                    .getCollection("zl_carry_" + new ObjectId().toHexString());
            try {
                List<Document> many = new ArrayList<>();
                for (int i = 0; i < 40; i++) {
                    many.add(new Document("_id", i));
                }
                things.insertMany(many);
                long id;
                try (ClientSession session = client.startSession()) {
                    MongoCursor<Document> leftOpen = things.find(session).batchSize(5).cursor();
                    leftOpen.next();
                    id = leftOpen.getServerCursor().getId();
                    assertTrue(idleCursors(client).contains(id), "the cursor is open");
                    // not closed by the application
                }
                assertFalse(idleCursors(client).contains(id),
                        "the cursor outlived its session and stays reachable under its lsid");
            } finally {
                things.drop();
            }
        }
    }

    /** The pooled server session comes back without the last user's transaction. */
    @Test
    void aReusedSessionStartsClean() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            Object firstId;
            try (ClientSession first = client.startSession()) {
                firstId = first.getServerSession().getIdentifier();
                first.startTransaction();
            }
            try (ClientSession second = client.startSession()) {
                assertEquals(firstId, second.getServerSession().getIdentifier(),
                        "the pool gives the server session back - which is what is tested");
                assertFalse(second.hasActiveTransaction());
                assertEquals(null, second.getOperationTime());
            }
        }
    }

    /** maxIdleTimeMS: a connection idle longer is closed, not lent; without it, it is lent again. */
    @Test
    void anIdleConnectionPastItsTimeIsNotLent() throws Exception {
        try (MongoClient client = SeclumeMongoClients.create(url + "&maxIdleTimeMS=300")) {
            long first = connectionId(client);
            assertEquals(first, connectionId(client), "at once, the same connection");
            Thread.sleep(600);
            assertNotEquals(first, connectionId(client));
        }
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            long first = connectionId(client);
            Thread.sleep(600);
            assertEquals(first, connectionId(client));
        }
    }

    private static long connectionId(MongoClient client) {
        return client.getDatabase("admin").runCommand(new Document("hello", 1))
                .get("connectionId", Number.class).longValue();
    }

    private static List<Long> idleCursors(MongoClient client) {
        List<Long> ids = new ArrayList<>();
        client.getDatabase("admin").aggregate(List.of(
                new Document("$currentOp", new Document("idleCursors", true)),
                new Document("$match", new Document("type", "idleCursor"))))
                .forEach(op -> ids.add(op.get("cursor", Document.class)
                        .get("cursorId", Number.class).longValue()));
        return ids;
    }
}
