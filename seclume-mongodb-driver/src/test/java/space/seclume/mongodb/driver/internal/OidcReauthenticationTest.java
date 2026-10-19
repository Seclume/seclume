package space.seclume.mongodb.driver.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import org.bson.BsonBinaryReader;
import org.bson.BsonBinaryWriter;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonString;
import org.bson.codecs.BsonDocumentCodec;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.EncoderContext;
import org.bson.io.BasicOutputBuffer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.mongodb.MongoCommandException;
import com.mongodb.ServerAddress;

import space.seclume.internal.TlsLayer;
import space.seclume.internal.Transport;
import space.seclume.mongodb.MongoUrl;

/**
 * ReauthenticationRequired (391): an OIDC token expired under a connection.
 * The session reads its token again, logs in again and runs the command once
 * more - and only once: a server that keeps asking gets its error back.
 */
class OidcReauthenticationTest {

    /** A server in a TLS layer: each request answered by {@code answer}. */
    private static final class Played implements TlsLayer {
        private final Function<BsonDocument, BsonDocument> answer;
        private final ArrayDeque<ByteBuffer> replies = new ArrayDeque<>();
        final List<BsonDocument> requests = new ArrayList<>();

        Played(Function<BsonDocument, BsonDocument> answer) {
            this.answer = answer;
        }

        @Override
        public void write(ByteBuffer plain) {
            ByteBuffer in = plain.duplicate().order(ByteOrder.LITTLE_ENDIAN);
            int start = in.position();
            int length = in.getInt(start);
            int requestId = in.getInt(start + 4);
            byte[] body = new byte[length - 21];
            in.position(start + 21).get(body);
            BsonDocument request = decode(body);
            requests.add(request);
            byte[] reply = encode(answer.apply(request));
            ByteBuffer message = ByteBuffer.allocate(21 + reply.length)
                    .order(ByteOrder.LITTLE_ENDIAN);
            message.putInt(21 + reply.length).putInt(1).putInt(requestId).putInt(2013)
                    .putInt(0).put((byte) 0).put(reply);
            replies.add(message.flip());
        }

        @Override
        public int read(ByteBuffer target) {
            ByteBuffer next = replies.peek();
            int n = Math.min(target.remaining(), next.remaining());
            target.put(next.duplicate().limit(next.position() + n));
            next.position(next.position() + n);
            if (!next.hasRemaining()) {
                replies.poll();
            }
            return n;
        }

        @Override
        public X509Certificate peerCertificate() {
            return null;
        }

        @Override
        public String description() {
            return "played";
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

    private static BsonDocument decode(byte[] bytes) {
        try (BsonBinaryReader reader = new BsonBinaryReader(ByteBuffer.wrap(bytes))) {
            return new BsonDocumentCodec().decode(reader, DecoderContext.builder().build());
        }
    }

    private static byte[] encode(BsonDocument document) {
        BasicOutputBuffer out = new BasicOutputBuffer();
        try (BsonBinaryWriter writer = new BsonBinaryWriter(out)) {
            new BsonDocumentCodec().encode(writer, document, EncoderContext.builder().build());
        }
        return out.toByteArray();
    }

    private static final BsonDocument OK = new BsonDocument("ok", new BsonInt32(1));
    private static final BsonDocument EXPIRED = new BsonDocument("ok", new BsonInt32(0))
            .append("code", new BsonInt32(391))
            .append("codeName", new BsonString("ReauthenticationRequired"))
            .append("errmsg", new BsonString("the token expired"));
    private static final BsonDocument LOGGED_IN = new BsonDocument("ok", new BsonInt32(1))
            .append("conversationId", new BsonInt32(1)).append("done", BsonBoolean.TRUE);

    private static MongoSession session(Played played, Path token) {
        MongoUrl url = MongoUrl.parse("mongodb://db.example:27017/?authMechanism=MONGODB-OIDC"
                + "&token-provider=file&token-path=" + token.toString().replace('\\', '/'));
        return MongoSession.resume(new MongoSession.Detached(NOWHERE, played,
                new BsonDocument("maxWireVersion", new BsonInt32(25)),
                new ServerAddress("db.example", 27017)), url);
    }

    @Test
    void anExpiredTokenIsReplacedAndTheCommandRunsAgain(@TempDir Path dir) throws Exception {
        Path token = dir.resolve("token");
        Files.writeString(token, "first.token.jwt");
        int[] pings = {0};
        Played played = new Played(request -> {
            if (request.containsKey("saslStart")) {
                return LOGGED_IN;
            }
            return pings[0]++ == 0 ? EXPIRED : OK;
        });
        try (MongoSession session = session(played, token)) {
            // The token was renewed on disk in the meantime: the new one is the one sent.
            Files.writeString(token, "second.token.jwt");
            assertEquals(1, session.command("admin", new BsonDocument("ping", new BsonInt32(1)))
                    .getInt32("ok").getValue());
        }
        assertEquals(List.of("ping", "saslStart", "ping"),
                played.requests.stream().map(BsonDocument::getFirstKey).toList());
        BsonDocument login = played.requests.get(1);
        assertEquals("MONGODB-OIDC", login.getString("mechanism").getValue());
        assertEquals("second.token.jwt", decode(login.getBinary("payload").getData())
                .getString("jwt").getValue());
    }

    @Test
    void aServerThatKeepsAskingGetsItsErrorBack(@TempDir Path dir) throws Exception {
        Path token = dir.resolve("token");
        Files.writeString(token, "a.b.c");
        Played played = new Played(request -> request.containsKey("saslStart") ? LOGGED_IN
                : EXPIRED);
        try (MongoSession session = session(played, token)) {
            MongoCommandException refused = assertThrows(MongoCommandException.class,
                    () -> session.command("admin", new BsonDocument("ping", new BsonInt32(1))));
            assertEquals(391, refused.getErrorCode());
        }
        assertEquals(List.of("ping", "saslStart", "ping"),
                played.requests.stream().map(BsonDocument::getFirstKey).toList(),
                "logged in again more than once");
    }
}
