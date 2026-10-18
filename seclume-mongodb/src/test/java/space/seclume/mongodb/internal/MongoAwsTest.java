package space.seclume.mongodb.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLException;

import org.bson.BsonBinary;
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

import space.seclume.internal.TlsLayer;
import space.seclume.internal.Transport;
import space.seclume.secret.SecretProviders;
import space.seclume.tck.NoSecretInHeap;

/**
 * MONGODB-AWS against a server played here: the conversation's shape, the
 * signature against SigV4 computed independently with the JDK's HMAC from the
 * AWS specification, the server answers that are refused, and the key and
 * the session token absent from the heap afterwards.
 *
 * <p>Not against a real server: MONGODB-AWS is Atlas and Enterprise only, and
 * neither is a fixture here.
 */
class MongoAwsTest {

    /** AWS's documentation example key - not a key of anything. */
    private static final String SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String TOKEN = "FwoGZXIvYXdzEXAMPLETOKEN//////////wEaDEXAMPLE";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-19T08:30:00Z"),
            ZoneOffset.UTC);

    /** A TLS layer that is a server: each request answered by {@code answer}. */
    private static final class Played implements TlsLayer {
        private final Function<BsonDocument, BsonDocument> answer;
        private final ArrayDeque<ByteBuffer> replies = new ArrayDeque<>();
        final java.util.List<BsonDocument> requests = new java.util.ArrayList<>();

        Played(Function<BsonDocument, BsonDocument> answer) {
            this.answer = answer;
        }

        @Override
        public void write(ByteBuffer plain) {
            ByteBuffer in = plain.duplicate().order(ByteOrder.LITTLE_ENDIAN);
            int length = in.getInt(in.position());
            byte[] body = new byte[length - 21];
            in.position(in.position() + 21).get(body);
            BsonDocument request = decode(body);
            requests.add(request);
            replies.add(message(answer.apply(request)));
        }

        @Override
        public int read(ByteBuffer target) {
            ByteBuffer next = replies.peek();
            int n = Math.min(target.remaining(), next.remaining());
            ByteBuffer slice = next.duplicate().limit(next.position() + n);
            target.put(slice);
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
            return false;
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

    private static ByteBuffer message(BsonDocument body) {
        byte[] bytes = encode(body);
        ByteBuffer message = ByteBuffer.allocate(21 + bytes.length).order(ByteOrder.LITTLE_ENDIAN);
        message.putInt(21 + bytes.length).putInt(99).putInt(0).putInt(2013).putInt(0)
                .put((byte) 0).put(bytes);
        return message.flip();
    }

    private static BsonDocument payload(BsonDocument command) {
        return decode(command.getBinary("payload").getData());
    }

    /** An STS-minded server: a nonce that extends ours, then whatever the test says. */
    private static Function<BsonDocument, BsonDocument> server(String stsHost,
            Function<byte[], byte[]> serverNonce, Function<BsonDocument, BsonDocument> second) {
        return request -> {
            if (request.containsKey("saslStart")) {
                byte[] r = payload(request).getBinary("r").getData();
                BsonDocument answer = new BsonDocument("s", new BsonBinary(serverNonce.apply(r)))
                        .append("h", new BsonString(stsHost));
                return new BsonDocument("ok", new BsonInt32(1))
                        .append("conversationId", new BsonInt32(1))
                        .append("done", BsonBoolean.FALSE)
                        .append("payload", new BsonBinary(encode(answer)));
            }
            return second.apply(request);
        };
    }

    private static byte[] extend(byte[] clientNonce) {
        byte[] nonce = new byte[64];
        System.arraycopy(clientNonce, 0, nonce, 0, 32);
        for (int i = 32; i < 64; i++) {
            nonce[i] = (byte) i;
        }
        return nonce;
    }

    private static MongoAws.Credentials credentials(Path dir) throws IOException {
        Path key = dir.resolve("aws.key");
        Files.writeString(key, SECRET);
        Path token = dir.resolve("aws.token");
        Files.writeString(token, TOKEN);
        return new MongoAws.Credentials(null, "AKIDEXAMPLE",
                SecretProviders.of(Map.of("provider", "file", "path", key.toString())),
                SecretProviders.of(Map.of("provider", "file", "path", token.toString())));
    }

    private static final BsonDocument DONE = new BsonDocument("ok", new BsonInt32(1))
            .append("conversationId", new BsonInt32(1)).append("done", BsonBoolean.TRUE)
            .append("payload", new BsonBinary(new byte[0]));

    @Test
    void theSignatureIsSigV4OfGetCallerIdentity(@TempDir Path dir) throws Exception {
        Played played = new Played(server("sts.amazonaws.com", MongoAwsTest::extend,
                request -> DONE));
        MongoAws.authenticate(played, credentials(dir), "db", 27017, CLOCK);

        BsonDocument start = played.requests.get(0);
        assertEquals("MONGODB-AWS", start.getString("mechanism").getValue());
        assertEquals("$external", start.getString("$db").getValue());
        BsonDocument first = payload(start);
        assertEquals(32, first.getBinary("r").getData().length);
        assertEquals('n', first.getInt32("p").getValue());

        BsonDocument second = payload(played.requests.get(1));
        assertEquals("20261019T083000Z", second.getString("d").getValue());
        assertEquals(TOKEN, second.getString("t").getValue());
        byte[] serverNonce = extend(first.getBinary("r").getData());
        assertEquals(expectedAuthorization("sts.amazonaws.com", "us-east-1",
                "20261019T083000Z", "20261019", serverNonce),
                second.getString("a").getValue());
    }

    /** SigV4 from the AWS documentation, with the JDK's HMAC - not seclume's code. */
    private static String expectedAuthorization(String host, String region, String date,
            String day, byte[] serverNonce) throws Exception {
        String body = "Action=GetCallerIdentity&Version=2011-06-15";
        String signed = "content-length;content-type;host;x-amz-date;x-amz-security-token;"
                + "x-mongodb-gs2-cb-flag;x-mongodb-server-nonce";
        String canonical = "POST\n/\n\n"
                + "content-length:" + body.length() + "\n"
                + "content-type:application/x-www-form-urlencoded\n"
                + "host:" + host + "\n"
                + "x-amz-date:" + date + "\n"
                + "x-amz-security-token:" + TOKEN + "\n"
                + "x-mongodb-gs2-cb-flag:n\n"
                + "x-mongodb-server-nonce:" + Base64.getEncoder().encodeToString(serverNonce)
                + "\n\n" + signed + "\n" + hex(sha256(body));
        String scope = day + "/" + region + "/sts/aws4_request";
        String toSign = "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex(sha256(canonical));
        byte[] key = hmac(("AWS4" + SECRET).getBytes(StandardCharsets.UTF_8), day);
        key = hmac(key, region);
        key = hmac(key, "sts");
        key = hmac(key, "aws4_request");
        return "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/" + scope + ", SignedHeaders=" + signed
                + ", Signature=" + hex(hmac(key, toSign));
    }

    private static byte[] hmac(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] sha256(String data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    @Test
    void aServerNonceThatIsNotOursIsRefused(@TempDir Path dir) throws Exception {
        MongoAws.Credentials credentials = credentials(dir);
        Played wrongPrefix = new Played(server("sts.amazonaws.com", r -> new byte[64],
                request -> DONE));
        SSLException refused = assertThrows(SSLException.class,
                () -> MongoAws.authenticate(wrongPrefix, credentials, "db", 27017, CLOCK));
        assertTrue(refused.getMessage().contains("does not begin with ours"));
        Played tooShort = new Played(server("sts.amazonaws.com",
                r -> java.util.Arrays.copyOf(r, 40), request -> DONE));
        assertThrows(SSLException.class,
                () -> MongoAws.authenticate(tooShort, credentials, "db", 27017, CLOCK));
        assertEquals(1, tooShort.requests.size(), "something was signed for a bad nonce");
    }

    @Test
    void anStsHostThatIsNoHostIsRefused(@TempDir Path dir) throws Exception {
        MongoAws.Credentials credentials = credentials(dir);
        for (String bad : new String[] {"", "sts..amazonaws.com", ".sts.amazonaws.com",
                "x".repeat(256)}) {
            Played played = new Played(server(bad, MongoAwsTest::extend, request -> DONE));
            assertThrows(SSLException.class,
                    () -> MongoAws.authenticate(played, credentials, "db", 27017, CLOCK), bad);
        }
        assertEquals("us-west-2", MongoAws.region("sts.us-west-2.amazonaws.com"));
        assertEquals("us-east-1", MongoAws.region("sts.amazonaws.com"));
    }

    @Test
    void aRefusalSaysSo(@TempDir Path dir) throws Exception {
        Played played = new Played(server("sts.amazonaws.com", MongoAwsTest::extend,
                request -> new BsonDocument("ok", new BsonInt32(0))
                        .append("errmsg", new BsonString("Authentication failed"))
                        .append("code", new BsonInt32(18))));
        SSLException refused = assertThrows(SSLException.class,
                () -> MongoAws.authenticate(played, credentials(dir), "db", 27017, CLOCK));
        assertTrue(refused.getMessage().contains("refused the AWS credentials"));
    }

    /** The key and the token were read and used - and are nowhere on the heap. */
    @Test
    void neitherTheKeyNorTheTokenIsLeftOnTheHeap(@TempDir Path dir) throws Exception {
        Path key = dir.resolve("aws.key");
        Path token = dir.resolve("aws.token");
        // Made here and written as bytes, so that this test itself holds them as no String.
        byte[] secret = new byte[40];
        byte[] session = new byte[200];
        java.security.SecureRandom random = new java.security.SecureRandom();
        for (byte[] bytes : new byte[][] {secret, session}) {
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) ('A' + random.nextInt(26));
            }
        }
        Files.write(key, secret);
        Files.write(token, session);
        java.util.Arrays.fill(secret, (byte) 0);
        java.util.Arrays.fill(session, (byte) 0);
        MongoAws.Credentials credentials = new MongoAws.Credentials(null, "AKIDEXAMPLE",
                SecretProviders.of(Map.of("provider", "file", "path", key.toString())),
                SecretProviders.of(Map.of("provider", "file", "path", token.toString())));
        Played played = new Played(server("sts.amazonaws.com", MongoAwsTest::extend,
                request -> DONE));
        MongoAws.authenticate(played, credentials, "db", 27017, CLOCK);
        played.requests.clear();                // the played server kept the token it got
        NoSecretInHeap.assertAbsent(key);
        NoSecretInHeap.assertAbsent(token);
    }
}
