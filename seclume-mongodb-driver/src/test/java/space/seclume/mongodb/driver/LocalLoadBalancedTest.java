package space.seclume.mongodb.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.bson.BsonValue;
import org.bson.Document;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.mongodb.client.ClientSession;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.model.Filters;
import com.mongodb.connection.ClusterType;
import com.mongodb.connection.ServerType;

import space.seclume.mongodb.MongoUrl;
import space.seclume.mongodb.driver.internal.MongoSession;
import space.seclume.tck.TestHosts;

/**
 * Against two mongos behind HAProxy, round robin (the
 * {@code mongo_lb_fixtures.sh} fixture on 27050): consecutive connections
 * reach different routers, so a cursor whose {@code getMore} or a
 * transaction whose next statement took another connection would fail -
 * the cursor is unknown on the other router, so is the transaction. An idle
 * connection is not reused after a millisecond ({@code maxIdleTimeMS=1}) and
 * the tests pause between commands: every command that is not pinned opens a
 * new connection, the next router. Skipped without the fixture.
 */
@Timeout(300)
class LocalLoadBalancedTest {

    private static String host;
    private static String url;

    @BeforeAll
    static void needsTheBalancer() {
        host = System.getProperty("seclume.mongo.host", TestHosts.database());
        Path password = find(".local-mongo-lb-password");
        Path ca = find(".local-mongo-lb-ca.pem");
        assumeTrue(password != null && ca != null, "no load balancer fixture files");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, 27050), 2000);
        } catch (IOException e) {
            assumeTrue(false, "no load balancer on " + host + ":27050");
        }
        url = "mongodb://seclume_test@" + host + ":27050/?loadBalanced=true&authSource=admin"
                + "&provider=file&path=" + password.toString().replace('\\', '/')
                + "&tlsRootCert=" + ca.toString().replace('\\', '/')
                + "&maxIdleTimeMS=1";
    }

    /** Longer than maxIdleTimeMS: a connection given back is not lent again. */
    private static void pause() {
        try {
            Thread.sleep(3);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static Path find(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    /** The fixture works as this test needs it: two connections, two routers. */
    @Test
    void consecutiveConnectionsReachDifferentRouters() {
        MongoUrl parsed = MongoUrl.parse(url);
        try (MongoSession first = MongoSession.open(parsed, host, 27050, true);
             MongoSession second = MongoSession.open(parsed, host, 27050, true)) {
            BsonValue one = first.helloReply().get("serviceId");
            BsonValue other = second.helloReply().get("serviceId");
            assertTrue(one != null && other != null, "the routers name no service");
            assertNotEquals(one, other, "both connections reached the same router");
        }
    }

    @Test
    void theBalancerIsTheOneServerAndCommandsRun() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> orders = fresh(client, "lb_basic");
            orders.insertOne(new Document("_id", 1).append("sku", "a"));
            assertEquals("a", orders.find(Filters.eq("_id", 1)).first().getString("sku"));
            assertEquals(ClusterType.LOAD_BALANCED, client.getClusterDescription().getType());
            assertEquals(ServerType.LOAD_BALANCER, client.getClusterDescription()
                    .getServerDescriptions().get(0).getType());
        }
    }

    /**
     * Cursors read in small batches side by side: each holds the connection
     * it was opened on. Without that, every other getMore would go to the
     * router that never heard of the cursor (CursorNotFound).
     */
    @Test
    void cursorsKeepTheirRouterAcrossGetMore() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> orders = fresh(client, "lb_cursor");
            List<Document> documents = new ArrayList<>();
            for (int i = 0; i < 300; i++) {
                documents.add(new Document("_id", i));
            }
            orders.insertMany(documents);
            List<MongoCursor<Document>> cursors = new ArrayList<>();
            for (int c = 0; c < 4; c++) {
                cursors.add(orders.find().sort(new Document("_id", 1)).batchSize(7).iterator());
            }
            int[] read = new int[cursors.size()];
            boolean more = true;
            while (more) {
                more = false;
                for (int c = 0; c < cursors.size(); c++) {
                    if (cursors.get(c).hasNext()) {
                        assertEquals(read[c]++, cursors.get(c).next().getInteger("_id"));
                        more = true;
                        if (read[c] % 7 == 0) {
                            pause();                     // before the next getMore
                        }
                    }
                }
            }
            for (int count : read) {
                assertEquals(300, count);
            }
        }
    }

    /**
     * A transaction's statements, reads and a cursor inside it all on the
     * router that began it; an aborted one leaves nothing.
     */
    @Test
    void transactionsStayOnTheirRouter() {
        try (MongoClient client = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> orders = fresh(client, "lb_tx");
            orders.insertOne(new Document("_id", "seed"));
            try (ClientSession session = client.startSession()) {
                session.startTransaction();
                for (int i = 0; i < 20; i++) {
                    orders.insertOne(session, new Document("_id", i));
                    pause();
                    assertEquals(i + 2, orders.countDocuments(session));
                    pause();
                }
                int seen = 0;
                try (MongoCursor<Document> cursor = orders.find(session).batchSize(3).iterator()) {
                    while (cursor.hasNext()) {
                        cursor.next();
                        seen++;
                        pause();
                    }
                }
                assertEquals(21, seen);
                session.commitTransaction();

                session.startTransaction();
                orders.insertOne(session, new Document("_id", "gone"));
                orders.deleteOne(session, Filters.eq("_id", "seed"));
                session.abortTransaction();
            }
            assertEquals(21, orders.countDocuments());
            assertEquals(1, orders.countDocuments(Filters.eq("_id", "seed")));
        }
    }

    /**
     * Every pinned connection comes back: with a pool of two, a cursor, a
     * cursor given up early, a commit and an abort, many times over - one
     * that was kept would leave the next borrow waiting until it times out.
     */
    @Test
    void pinnedConnectionsAreGivenBack() {
        try (MongoClient client = SeclumeMongoClients.create(url
                + "&maxPoolSize=2&waitQueueTimeoutMS=5000")) {
            MongoCollection<Document> orders = fresh(client, "lb_pool");
            List<Document> documents = new ArrayList<>();
            for (int i = 0; i < 50; i++) {
                documents.add(new Document("_id", i));
            }
            orders.insertMany(documents);
            for (int round = 0; round < 10; round++) {
                int all = orders.find().batchSize(5).into(new ArrayList<>()).size();
                assertEquals(50 + round, all);         // one committed per round before
                try (MongoCursor<Document> early = orders.find().batchSize(5).iterator()) {
                    early.next();
                }
                try (ClientSession session = client.startSession()) {
                    session.startTransaction();
                    orders.insertOne(session, new Document("_id", "r" + round));
                    session.commitTransaction();
                    session.startTransaction();
                    orders.insertOne(session, new Document("_id", "x" + round));
                    session.abortTransaction();
                }
            }
            assertEquals(60, orders.countDocuments());
        }
    }

    private static MongoCollection<Document> fresh(MongoClient client, String name) {
        MongoCollection<Document> collection = client.getDatabase("seclume_test")
                .getCollection(name);
        collection.drop();
        client.getDatabase("seclume_test").createCollection(name);
        return collection;
    }
}
