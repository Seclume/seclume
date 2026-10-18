package space.seclume.mongodb.driver.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.bson.BsonArray;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonString;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.mongodb.ReadPreference;
import com.mongodb.TransactionOptions;

import space.seclume.mongodb.MongoUrl;
import space.seclume.tck.TestHosts;

/**
 * A logged-in connection taken up by another session object, and a logical
 * session - a transaction in progress - carried on by another client.
 */
@Timeout(120)
class LocalCarryOnTest {

    private static final String HOST = System.getProperty("seclume.mongo.host",
            TestHosts.database());

    private static Path find(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static MongoUrl url(String hosts, String ca, String more) {
        Path password = find(".local-mongo-password");
        Path caFile = find(ca);
        assumeTrue(password != null && caFile != null, "no MongoDB fixture files");
        return MongoUrl.parse("mongodb://seclume_test@" + hosts + "/?authSource=admin"
                + "&provider=file&path=" + password.toString().replace('\\', '/')
                + "&tlsRootCert=" + caFile.toString().replace('\\', '/') + more);
    }

    private static void reachable(int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(HOST, port), 2000);
        } catch (IOException e) {
            assumeTrue(false, "no MongoDB on " + HOST + ":" + port);
        }
    }

    private static BsonDocument ping() {
        return new BsonDocument("ping", new BsonInt32(1));
    }

    @Test
    void aConnectionGoesOnUnderAnotherSession() {
        reachable(27017);
        MongoSession first = MongoSession.open(url(HOST + ":27017", ".local-mongo-ca.pem", ""),
                HOST, 27017);
        first.command("admin", ping());
        MongoSession.Detached described = first.snapshot();
        assertSame(described.tls(), first.detach().tls(), "the snapshot names the live layer");
        assertTrue(first.isClosed());
        assertThrows(com.mongodb.MongoSocketClosedException.class,
                () -> first.command("admin", ping()));
        try (MongoSession second = MongoSession.resume(described)) {
            BsonDocument status = second.command("admin",
                    new BsonDocument("connectionStatus", new BsonInt32(1)));
            assertEquals(1, status.getDocument("authInfo").getArray("authenticatedUsers").size(),
                    "the login went with the connection");
            assertEquals(first.maxMessageSize(), second.maxMessageSize());
        }
    }

    @Test
    void notWhileACommandIsInFlight() throws Exception {
        reachable(27017);
        try (MongoSession session = MongoSession.open(url(HOST + ":27017",
                ".local-mongo-ca.pem", ""), HOST, 27017)) {
            Thread busy = Thread.ofPlatform().start(() -> {
                try {
                    session.command("admin", new BsonDocument("aggregate", new BsonInt32(1))
                            .append("pipeline", new BsonArray(List.of(
                                    new BsonDocument("$documents",
                                            new BsonArray(List.of(new BsonDocument()))),
                                    new BsonDocument("$match", new BsonDocument("$expr",
                                            new BsonDocument("$function", new BsonDocument("body",
                                                    new BsonString("function() { sleep(1500); return true; }"))
                                                    .append("args", new BsonArray())
                                                    .append("lang", new BsonString("js"))))))))
                            .append("cursor", new BsonDocument()));
                } catch (RuntimeException ignored) {
                    // the point is the refusal below
                }
            });
            Thread.sleep(300);
            assertThrows(IllegalStateException.class, session::detach);
            assertThrows(IllegalStateException.class, session::snapshot);
            busy.join();
            session.command("admin", ping());                // and it went on undisturbed
        }
    }

    /** A transaction begun by one client is committed by another, which never logged that session in. */
    @Test
    void aTransactionIsCarriedOnByAnotherClient() {
        for (int port = 27021; port <= 27023; port++) {
            reachable(port);
        }
        String hosts = HOST + ":27021," + HOST + ":27022," + HOST + ":27023";
        MongoUrl url = url(hosts, ".local-mongo-rs-ca.pem", "&replicaSet=slm-rs");
        String collection = "zl_carry_" + new ObjectId().toHexString();
        try (Topology one = Topology.of(url); Topology two = Topology.of(url)) {
            one.write(null, "seclume_test", new BsonDocument("create", new BsonString(collection)),
                    null, null, false);
            LogicalSession started = one.acquire(true, true);
            started.startTransaction(TransactionOptions.builder().build());
            one.write(started, "seclume_test", new BsonDocument("insert",
                    new BsonString(collection)), "documents",
                    List.of(new BsonDocument("_id", new BsonInt32(1))), true);

            LogicalSession carried = LogicalSession.of(started.state());
            two.write(carried, "seclume_test", new BsonDocument("insert",
                    new BsonString(collection)), "documents",
                    List.of(new BsonDocument("_id", new BsonInt32(2))), true);
            assertEquals(0, count(two, null, collection), "nothing visible before the commit");
            assertEquals(2, count(two, carried, collection), "the transaction sees both");
            two.commit(carried);
            assertEquals(2, count(one, null, collection));
            one.write(null, "seclume_test", new BsonDocument("drop", new BsonString(collection)),
                    null, null, false);
        }
    }

    private static int count(Topology topology, LogicalSession session, String collection) {
        BsonDocument reply = topology.read(session, ReadPreference.primary(), "seclume_test",
                new BsonDocument("find", new BsonString(collection))).document();
        return reply.getDocument("cursor").getArray("firstBatch").size();
    }
}
