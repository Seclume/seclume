package space.seclume.mongodb.driver.internal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import org.bson.BsonArray;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonInt64;
import org.bson.BsonObjectId;
import org.bson.BsonString;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.mongodb.ServerAddress;
import com.mongodb.connection.ServerDescription;
import com.mongodb.connection.ServerType;

import space.seclume.mongodb.MongoUrl;

/**
 * What a {@code hello} does to the topology - and what one that cannot be
 * read does not do: end the monitor. It is one thread, the only one that
 * looks at the servers; a {@code hello} with a field of another type than
 * expected was an exception thrown through it, and from then on no server was
 * looked at again - a primary that stepped down stayed the primary for this
 * client, and one that went away was waited for until the selection timed out.
 */
class TopologyHelloTest {

    private static final ServerAddress FIRST = new ServerAddress("db1.example", 27017);
    private static final ServerAddress SECOND = new ServerAddress("db2.example", 27017);
    private static final ObjectId PROCESS = new ObjectId();

    private Topology topology;

    @BeforeEach
    void aReplicaSetOfTwo(@TempDir Path dir) throws Exception {
        Path token = dir.resolve("token");
        Files.writeString(token, "a.test.token");
        topology = Topology.unmonitored(MongoUrl.parse("mongodb://db1.example:27017,"
                + "db2.example:27017/?replicaSet=rs0&authMechanism=MONGODB-OIDC"
                + "&token-provider=file&token-path=" + token.toString().replace('\\', '/')));
    }

    @AfterEach
    void close() {
        topology.close();
    }

    private static BsonDocument primary(long counter) {
        return new BsonDocument("isWritablePrimary", BsonBoolean.TRUE)
                .append("setName", new BsonString("rs0"))
                .append("hosts", new BsonArray(List.of(new BsonString("db1.example:27017"),
                        new BsonString("db2.example:27017"))))
                .append("maxWireVersion", new BsonInt32(25))
                .append("logicalSessionTimeoutMinutes", new BsonInt32(30))
                .append("topologyVersion", new BsonDocument("processId",
                        new BsonObjectId(PROCESS)).append("counter", new BsonInt64(counter)))
                .append("ok", new BsonInt32(1));
    }

    private ServerDescription server(ServerAddress address) {
        for (ServerDescription description : topology.description().getServerDescriptions()) {
            if (description.getAddress().equals(address)) {
                return description;
            }
        }
        throw new AssertionError(address + " is not in " + topology.description());
    }

    @Test
    void aPrimarysHelloMakesItThePrimary() {
        assertEquals(ServerType.UNKNOWN, server(FIRST).getType());
        topology.heard(FIRST, primary(1), 1_000_000);
        assertEquals(ServerType.REPLICA_SET_PRIMARY, server(FIRST).getType());
        assertEquals(ServerType.UNKNOWN, server(SECOND).getType());
    }

    @Test
    void aHelloThatCannotBeReadMakesTheServerUnknownAndNothingElse() {
        // What is wrong with each, put into a hello that is newer than the last good one.
        List<java.util.function.UnaryOperator<BsonDocument>> unreadable = List.of(
                h -> h.append("tags", new BsonDocument("dc", new BsonInt32(5))),
                h -> h.append("hosts", new BsonString("db1.example:27017")),
                h -> h.append("hosts", new BsonArray(List.of(new BsonInt32(27017)))),
                h -> h.append("hosts", new BsonArray(List.of(
                        new BsonString("db3.example:not-a-port")))),
                h -> h.append("electionId", new BsonString("the newest")),
                h -> h.append("setName", new BsonInt32(0)),
                h -> h.append("topologyVersion", new BsonInt32(7)),
                h -> h.append("topologyVersion", new BsonDocument()),
                h -> h.append("lastWrite", new BsonString("just now")));
        long counter = 2;
        for (java.util.function.UnaryOperator<BsonDocument> wrong : unreadable) {
            topology.heard(FIRST, primary(counter++), 1_000_000);
            assertEquals(ServerType.REPLICA_SET_PRIMARY, server(FIRST).getType());

            BsonDocument hello = wrong.apply(primary(counter++));
            assertDoesNotThrow(() -> topology.heard(FIRST, hello, 1_000_000), hello.toJson());

            ServerDescription after = server(FIRST);
            assertEquals(ServerType.UNKNOWN, after.getType(), hello.toJson());
            assertNotNull(after.getException(), hello.toJson());
            assertTrue(after.getException().getMessage().contains("could not be read"),
                    after.getException().getMessage());
            assertEquals(2, topology.description().getServerDescriptions().size(),
                    "the other member stays known: " + hello.toJson());
        }
        // And the next good one is taken again.
        topology.heard(FIRST, primary(counter), 1_000_000);
        assertEquals(ServerType.REPLICA_SET_PRIMARY, server(FIRST).getType());
    }

    @Test
    void anOlderHelloOfTheSameProcessChangesNothing() {
        topology.heard(FIRST, primary(5), 1_000_000);
        BsonDocument secondary = primary(4).append("isWritablePrimary", BsonBoolean.FALSE)
                .append("secondary", BsonBoolean.TRUE);
        topology.heard(FIRST, secondary, 1_000_000);
        assertEquals(ServerType.REPLICA_SET_PRIMARY, server(FIRST).getType());
    }

    /**
     * Closing ends the pooled server sessions on a server that is known - and
     * does not wait the thirty seconds of a server selection for one when none
     * is: a client that never reached its cluster closed half a minute late.
     */
    @Test
    void closingDoesNotWaitForAServerThatIsNotThere() {
        topology.release(topology.acquire(false, false));
        assertTimeoutPreemptively(Duration.ofSeconds(10), topology::close);
    }
}
