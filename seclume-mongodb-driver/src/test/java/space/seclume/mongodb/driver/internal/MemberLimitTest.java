package space.seclume.mongodb.driver.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.bson.BsonArray;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonString;
import org.junit.jupiter.api.Test;

import com.mongodb.ServerAddress;
import com.mongodb.connection.ServerType;

/**
 * A primary could name as many members as it liked, and each got a pool and a
 * monitor. A replica set has at most 50; an answer naming more is a broken one.
 */
class MemberLimitTest {

    private static BsonDocument hello(int members) {
        BsonArray hosts = new BsonArray();
        for (int i = 0; i < members; i++) {
            hosts.add(new BsonString("m" + i + ".example:27017"));
        }
        return new BsonDocument("setName", new BsonString("rs0"))
                .append("isWritablePrimary", BsonBoolean.TRUE).append("hosts", hosts);
    }

    @Test
    void moreThanFiftyMembersIsABrokenAnswer() {
        var described = Topology.describe(new ServerAddress("m0.example", 27017), hello(51), 1);
        assertEquals(ServerType.UNKNOWN, described.getType());
        assertNotNull(described.getException());
    }

    @Test
    void fiftyAreRead() {
        var described = Topology.describe(new ServerAddress("m0.example", 27017), hello(50), 1);
        assertEquals(ServerType.REPLICA_SET_PRIMARY, described.getType());
        assertNull(described.getException());
        assertEquals(50, described.getHosts().size());
    }
}
