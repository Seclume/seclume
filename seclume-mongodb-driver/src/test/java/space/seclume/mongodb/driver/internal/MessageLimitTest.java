package space.seclume.mongodb.driver.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.cert.X509Certificate;

import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonInt64;
import org.bson.BsonString;
import org.bson.BsonValue;
import org.junit.jupiter.api.Test;

import com.mongodb.MongoClientException;
import com.mongodb.MongoInternalException;
import com.mongodb.ServerAddress;

import space.seclume.internal.TlsLayer;
import space.seclume.internal.Transport;

/**
 * The largest message is what the server's {@code hello} names - and never
 * more than the 48 MB every server has had. The {@code hello} is answered
 * before the login, and a reply's announced length is checked against that
 * number before the bytes for it are allocated: a peer that named 2 GB and
 * then announced a reply of 2 GB had the client allocate them.
 */
class MessageLimitTest {

    private static final ServerAddress ADDRESS = new ServerAddress("db.example", 27017);
    private static final int FORTY_EIGHT_MB = 48_000_000;

    private static BsonDocument hello(BsonValue maxMessageSizeBytes) {
        BsonDocument hello = new BsonDocument("maxWireVersion", new BsonInt32(25));
        if (maxMessageSizeBytes != null) {
            hello.put("maxMessageSizeBytes", maxMessageSizeBytes);
        }
        return hello;
    }

    @Test
    void whatTheServerNamesIsTheLimitUpToFortyEightMegabytes() {
        assertEquals(FORTY_EIGHT_MB, MongoSession.messageLimit(hello(null), ADDRESS));
        assertEquals(FORTY_EIGHT_MB, MongoSession.messageLimit(
                hello(new BsonInt32(FORTY_EIGHT_MB)), ADDRESS));
        assertEquals(1_000_000, MongoSession.messageLimit(
                hello(new BsonInt32(1_000_000)), ADDRESS));
        assertEquals(FORTY_EIGHT_MB, MongoSession.messageLimit(
                hello(new BsonInt32(Integer.MAX_VALUE)), ADDRESS));
        assertEquals(FORTY_EIGHT_MB, MongoSession.messageLimit(
                hello(new BsonInt64(1L << 40)), ADDRESS));
    }

    @Test
    void aLimitThatIsNoneIsRefused() {
        for (BsonValue none : new BsonValue[] {new BsonInt32(0), new BsonInt32(-1),
            new BsonInt64(Long.MIN_VALUE), new BsonString("48000000")}) {
            MongoClientException refused = assertThrows(MongoClientException.class,
                    () -> MongoSession.messageLimit(hello(none), ADDRESS), none.toString());
            assertTrue(refused.getMessage().contains("maxMessageSizeBytes"), refused.getMessage());
        }
    }

    /** A peer that answers every command with a header announcing {@code announced} bytes. */
    private static final class Announcing implements TlsLayer {
        private final int announced;
        private ByteBuffer header;

        Announcing(int announced) {
            this.announced = announced;
        }

        @Override
        public void write(ByteBuffer plain) {
            int requestId = plain.duplicate().order(ByteOrder.LITTLE_ENDIAN)
                    .getInt(plain.position() + 4);
            header = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
            header.putInt(announced).putInt(1).putInt(requestId).putInt(2013).flip();
            plain.position(plain.limit());
        }

        @Override
        public int read(ByteBuffer target) {
            if (header == null || !header.hasRemaining()) {
                return -1;                           // nothing follows the header
            }
            int n = Math.min(target.remaining(), header.remaining());
            target.put(header.duplicate().limit(header.position() + n));
            header.position(header.position() + n);
            return n;
        }

        @Override
        public X509Certificate peerCertificate() {
            return null;
        }

        @Override
        public String description() {
            return "announcing";
        }

        @Override
        public boolean movable() {
            return true;
        }

        @Override
        public void replaceTransport(Transport replacement) {
        }

        @Override
        public void discard() {
        }

        @Override
        public void close() {
        }
    }

    private static final Transport NOWHERE = new Transport() {
        @Override
        public int read(ByteBuffer into) {
            return -1;
        }

        @Override
        public int write(ByteBuffer from) {
            return 0;
        }

        @Override
        public boolean isOpen() {
            return true;
        }

        @Override
        public void close() {
        }
    };

    @Test
    void aReplyAnnouncedLargerThanThatIsRefusedBeforeItIsAllocated() {
        int announced = Integer.MAX_VALUE - 64;
        MongoSession session = MongoSession.resume(new MongoSession.Detached(NOWHERE,
                new Announcing(announced), hello(new BsonInt32(Integer.MAX_VALUE)), ADDRESS));
        assertEquals(FORTY_EIGHT_MB, session.maxMessageSize());
        MongoInternalException refused = assertThrows(MongoInternalException.class,
                () -> session.command("admin", new BsonDocument("ping", new BsonInt32(1))));
        assertTrue(refused.getMessage().contains("announced a reply of " + announced),
                refused.getMessage());
        assertTrue(refused.getMessage().contains("at most " + FORTY_EIGHT_MB),
                refused.getMessage());
        assertTrue(session.isClosed(), "a connection that announced it is not used again");
    }
}
