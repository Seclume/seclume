package space.seclume.mongodb.driver.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
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
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.bson.BsonArray;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonString;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.mongodb.MongoCommandException;
import com.mongodb.MongoException;
import com.mongodb.MongoSocketClosedException;
import com.mongodb.MongoSocketReadTimeoutException;

import space.seclume.mongodb.MongoUrl;
import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.TestHosts;

/**
 * The session core against the MongoDB 8 fixture (requireTLS, SCRAM-SHA-1 and
 * SCRAM-SHA-256 both offered to the user). Skipped when the fixture or its
 * files are not there.
 */
@Timeout(120)
class LocalMongoSessionTest {

    private static String host;
    private static int port;
    private static Path passwordFile;
    private static Path caFile;

    @BeforeAll
    static void needsTheFixture() {
        host = System.getProperty("seclume.mongo.host", TestHosts.database());
        port = Integer.getInteger("seclume.mongo.port", 27017);
        passwordFile = find(".local-mongo-password");
        caFile = find(".local-mongo-ca.pem");
        assumeTrue(passwordFile != null, "no .local-mongo-password");
        assumeTrue(caFile != null, "no .local-mongo-ca.pem");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException e) {
            assumeTrue(false, "no MongoDB on " + host + ":" + port);
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

    private static MongoSession open(String options) {
        MongoUrl url = MongoUrl.parse("mongodb://seclume_test@" + host + ":" + port
                + "/?authSource=admin&provider=file&path="
                + passwordFile.toString().replace('\\', '/')
                + "&tlsRootCert=" + caFile.toString().replace('\\', '/') + options);
        return MongoSession.open(url, host, port);
    }

    @Test
    void helloThenLoginThenCommands() throws Exception {
        try (MongoSession session = open("")) {
            assertTrue(session.maxWireVersion() >= MongoSession.MIN_WIRE_VERSION);
            assertTrue(session.helloReply().getArray("saslSupportedMechs")
                    .contains(new BsonString("SCRAM-SHA-256")));
            BsonDocument status = session.command("admin",
                    new BsonDocument("connectionStatus", new BsonInt32(1)));
            BsonArray users = status.getDocument("authInfo").getArray("authenticatedUsers");
            assertEquals(1, users.size(), status.toJson());
            assertEquals("seclume_test", users.get(0).asDocument().getString("user").getValue());
        }
        NoSecretInHeap.assertAbsent(passwordFile);
    }

    /** Documents go as a sequence and come back through a cursor reply. */
    @Test
    void insertAsASequenceAndFindThemAgain() {
        try (MongoSession session = open("")) {
            String collection = "zl_session_" + Long.toHexString(System.nanoTime());
            try {
                BsonDocument inserted = session.command("seclume_test",
                        new BsonDocument("insert", new BsonString(collection)), "documents",
                        List.of(new BsonDocument("_id", new BsonInt32(1)).append("v",
                                        new BsonString("one")),
                                new BsonDocument("_id", new BsonInt32(2)).append("v",
                                        new BsonString("two"))));
                assertEquals(2, inserted.getInt32("n").getValue(), inserted.toJson());
                BsonDocument found = session.command("seclume_test",
                        new BsonDocument("find", new BsonString(collection))
                                .append("filter", new BsonDocument("_id", new BsonInt32(2))));
                BsonArray batch = found.getDocument("cursor").getArray("firstBatch");
                assertEquals(1, batch.size());
                assertEquals("two", batch.get(0).asDocument().getString("v").getValue());
            } finally {
                session.command("seclume_test", new BsonDocument("drop",
                        new BsonString(collection)));
            }
        }
    }

    /**
     * compressors=zlib: agreed in hello, and the server's own counters show
     * that what it received came compressed.
     */
    @Test
    void zlibIsAgreedAndUsed() {
        try (MongoSession session = open("&compressors=zlib")) {
            assertTrue(session.compressed(), "the server did not agree to zlib");
            long before = zlibBytesIn(session);
            BsonDocument big = new BsonDocument("ping", new BsonInt32(1))
                    .append("comment", new BsonString("z".repeat(20_000)));
            session.command("admin", big);
            assertTrue(zlibBytesIn(session) > before, "nothing reached the server compressed");
        }
        try (MongoSession plain = open("")) {
            assertTrue(!plain.compressed());
        }
    }

    private static long zlibBytesIn(MongoSession session) {
        return session.command("admin", new BsonDocument("serverStatus", new BsonInt32(1)))
                .getDocument("network").getDocument("compression").getDocument("zlib")
                .getDocument("decompressor").getNumber("bytesIn").longValue();
    }

    /** A refused command is the API's exception with the server's code; the session goes on. */
    @Test
    void aRefusedCommandKeepsTheSession() {
        try (MongoSession session = open("")) {
            MongoCommandException refused = assertThrows(MongoCommandException.class,
                    () -> session.command("admin", new BsonDocument("noSuchCommand",
                            new BsonInt32(1))));
            assertEquals(59, refused.getErrorCode(), refused.getMessage());
            assertEquals("CommandNotFound", refused.getErrorCodeName());
            assertEquals(1.0, session.command("admin", new BsonDocument("ping",
                    new BsonInt32(1))).getNumber("ok").doubleValue());
        }
    }

    /** No reply within the network timeout: the session is closed, not read again. */
    @Test
    void aReadTimeoutEndsTheSession() {
        try (MongoSession session = open("")) {
            session.networkTimeout(300);
            MongoException timedOut = assertTimeoutPreemptively(Duration.ofSeconds(10),
                    () -> assertThrows(MongoException.class, () -> slow(session)));
            assumeTrue(!(timedOut instanceof MongoCommandException),
                    "the server runs no JavaScript: " + timedOut.getMessage());
            assertInstanceOf(MongoSocketReadTimeoutException.class, timedOut);
            assertTrue(session.isClosed(), "a session read past its timeout was kept");
            assertThrows(MongoSocketClosedException.class, () -> session.command("admin",
                    new BsonDocument("ping", new BsonInt32(1))));
        }
    }

    /** {@code abort} from another thread gives up a command that waits for its reply. */
    @Test
    void abortGivesUpACommandInFlight() throws Exception {
        try (MongoSession session = open("")) {
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread waiting = Thread.ofPlatform().start(() -> {
                try {
                    slow(session);
                } catch (Throwable e) {
                    failure.set(e);
                }
            });
            Thread.sleep(300);
            session.abort();
            waiting.join(10_000);
            assertTrue(!waiting.isAlive(), "the command still waits after abort");
            assumeTrue(!(failure.get() instanceof MongoCommandException),
                    "the server runs no JavaScript");
            assertInstanceOf(MongoSocketClosedException.class, failure.get());
            assertTrue(session.isClosed());
        }
    }

    /** A command that takes about three seconds on the server. */
    private static void slow(MongoSession session) {
        session.command("seclume_test", new BsonDocument("aggregate", new BsonInt32(1))
                .append("pipeline", new BsonArray(List.of(
                        new BsonDocument("$documents", new BsonArray(List.of(new BsonDocument()))),
                        new BsonDocument("$match", new BsonDocument("$expr",
                                new BsonDocument("$function", new BsonDocument("body",
                                        new BsonString("function() { sleep(3000); return true; }"))
                                        .append("args", new BsonArray())
                                        .append("lang", new BsonString("js"))))))))
                .append("cursor", new BsonDocument()));
    }
}
