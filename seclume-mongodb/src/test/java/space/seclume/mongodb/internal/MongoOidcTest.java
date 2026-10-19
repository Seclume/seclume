package space.seclume.mongodb.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import javax.net.ssl.SSLException;

import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonString;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.secret.SecretProviders;
import space.seclume.tck.NoSecretInHeap;

/** MONGODB-OIDC against a server played here (Atlas and Enterprise only, so no fixture). */
class MongoOidcTest {

    private static final BsonDocument DONE = new BsonDocument("ok", new BsonInt32(1))
            .append("conversationId", new BsonInt32(1)).append("done", BsonBoolean.TRUE);

    private static space.seclume.secret.SecretProvider file(Path path) {
        return SecretProviders.of(Map.of("provider", "file", "path", path.toString(),
                "max-length", "16384"));
    }

    @Test
    void theTokenGoesInOneStep(@TempDir Path dir) throws Exception {
        Path token = dir.resolve("token");
        Files.writeString(token, "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ3b3JrbG9hZCJ9.c2lnbmF0dXJl");
        MongoAwsTest.Played played = new MongoAwsTest.Played(request -> DONE);
        MongoOidc.authenticate(played, file(token), "db", 27017);
        assertEquals(1, played.requests.size());
        BsonDocument start = played.requests.get(0);
        assertEquals("MONGODB-OIDC", start.getString("mechanism").getValue());
        assertEquals("$external", start.getString("$db").getValue());
        assertEquals(Files.readString(token),
                MongoAwsTest.payload(start).getString("jwt").getValue());
    }

    @Test
    void aRefusedTokenSaysSo(@TempDir Path dir) throws Exception {
        Path token = dir.resolve("token");
        Files.writeString(token, "a.b.c");
        MongoAwsTest.Played played = new MongoAwsTest.Played(request ->
                new BsonDocument("ok", new BsonInt32(0)).append("code", new BsonInt32(18))
                        .append("errmsg", new BsonString("Authentication failed")));
        SSLException refused = assertThrows(SSLException.class,
                () -> MongoOidc.authenticate(played, file(token), "db", 27017));
        assertTrue(refused.getMessage().contains("refused the OIDC token"));
    }

    /** A line break inside the token (one at its end the file provider drops): refused before sending. */
    @Test
    void aLineBreakInTheTokenIsRefusedBeforeSending(@TempDir Path dir) throws Exception {
        Path token = dir.resolve("token");
        Files.writeString(token, "a.b\n.c");
        MongoAwsTest.Played played = new MongoAwsTest.Played(request -> DONE);
        SSLException refused = assertThrows(SSLException.class,
                () -> MongoOidc.authenticate(played, file(token), "db", 27017));
        assertTrue(refused.getMessage().contains("line break"), refused.getMessage());
        assertEquals(0, played.requests.size(), "a broken token was sent");
    }

    @Test
    void theTokenIsNotLeftOnTheHeap(@TempDir Path dir) throws Exception {
        Path token = dir.resolve("token");
        byte[] bytes = new byte[600];
        java.security.SecureRandom random = new java.security.SecureRandom();
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) ('a' + random.nextInt(26));
        }
        Files.write(token, bytes);
        java.util.Arrays.fill(bytes, (byte) 0);
        MongoAwsTest.Played played = new MongoAwsTest.Played(request -> DONE);
        MongoOidc.authenticate(played, file(token), "db", 27017);
        played.requests.clear();                 // the played server kept what it got
        NoSecretInHeap.assertAbsent(token);
    }
}
