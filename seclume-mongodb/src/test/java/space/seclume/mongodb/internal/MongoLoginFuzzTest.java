package space.seclume.mongodb.internal;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.function.Function;

import org.bson.BsonBinary;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonString;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.TlsLayer;
import space.seclume.internal.Transport;
import space.seclume.mongodb.MongoUrl;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretScope;

/**
 * Every login seclume does with MongoDB - SCRAM-SHA-256, MONGODB-AWS,
 * MONGODB-OIDC - against a server whose answers are spoilt: a bit, a byte,
 * a length that lies, a type byte, or the connection cut part-way.
 *
 * <p>The login is where the secret is read: the password, the AWS secret key
 * and session token, the OIDC token. Two things are asked of each case.
 * First, that it ends as a login that failed - an {@link IOException} - and
 * not as some other exception that escapes the session's handling, nor as a
 * hang or a large allocation; the replies are read by seclume's own off-heap
 * BSON reader, not the bson library's. Second, and the one that counts, that
 * {@link SecretScope#open()} is back where it started: a scope left open is
 * a secret still in this process, on a path nobody wrote a test for.
 *
 * <p>Seeded, so a failure is reproducible: the message names the case.
 * {@code -Dseclume.mongo.fuzz.rounds=N} runs more per mechanism,
 * {@code -Dseclume.mongo.fuzz.seed=S} others.
 */
@Timeout(600)
@Isolated
class MongoLoginFuzzTest {

    private static final int ROUNDS = Integer.getInteger("seclume.mongo.fuzz.rounds", 1_500);
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-19T08:30:00Z"),
            ZoneOffset.UTC);

    /** One login against a server; the replies are what the fuzzer spoils. */
    private interface Login {
        void run(TlsLayer tls) throws IOException;
    }

    @Test
    void scram(@TempDir Path dir) throws Exception {
        Path password = dir.resolve("pw");
        Files.writeString(password, "ein Testpasswort");
        MongoUrl url = MongoUrl.parse("mongodb://seclume_test@db:27017/?authSource=admin"
                + "&provider=file&path=" + password.toString().replace('\\', '/'));
        fuzz("scram", tls -> MongoHandshake.authenticate(tls, url, "db", 27017),
                MongoLoginFuzzTest::scramServer, 0x5C2A);
    }

    @Test
    void aws(@TempDir Path dir) throws Exception {
        Path key = dir.resolve("aws.key");
        Files.writeString(key, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        Path token = dir.resolve("aws.token");
        Files.writeString(token, "FwoGZXIvYXdzEXAMPLETOKEN");
        MongoAws.Credentials credentials = new MongoAws.Credentials(null, "AKIDEXAMPLE",
                SecretProviders.of(Map.of("provider", "file", "path", key.toString())),
                SecretProviders.of(Map.of("provider", "file", "path", token.toString())));
        fuzz("aws", tls -> MongoAws.authenticate(tls, credentials, "db", 27017, CLOCK),
                MongoLoginFuzzTest::awsServer, 0xA3);
    }

    @Test
    void oidc(@TempDir Path dir) throws Exception {
        Path token = dir.resolve("token");
        Files.writeString(token, "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln");
        var provider = SecretProviders.of(Map.of("provider", "file", "path", token.toString(),
                "max-length", "16384"));
        fuzz("oidc", tls -> MongoOidc.authenticate(tls, provider, "db", 27017),
                request -> done(), 0x01DC);
    }

    // ---- the fuzzer ------------------------------------------------------------

    private static void fuzz(String name, Login login,
            Function<BsonDocument, BsonDocument> server, long seed) {
        // One seed from outside, a different stream per mechanism.
        seed ^= Long.getLong("seclume.mongo.fuzz.seed", 0L);
        Random random = new Random(seed);
        Map<String, Integer> tally = new TreeMap<>();
        long readBefore = SecretScope.allocations();
        for (int round = 0; round < ROUNDS; round++) {
            Spoilt tls = new Spoilt(server, random);
            long open = SecretScope.open();
            try {
                login.run(tls);
                tally.merge("logged in", 1, Integer::sum);
            } catch (IOException refused) {
                tally.merge(refused.getClass().getSimpleName(), 1, Integer::sum);
            } catch (RuntimeException | StackOverflowError | OutOfMemoryError other) {
                fail(name + " seed " + seed + " round " + round + " (" + tls.what + "): "
                        + other, other);
            }
            if (SecretScope.open() != open) {
                fail(name + " seed " + seed + " round " + round + " (" + tls.what + ") left "
                        + (SecretScope.open() - open) + " secret scope(s) open");
            }
        }
        System.err.println("[login fuzz mongodb " + name + "] " + ROUNDS + " rounds, " + tally);
        assertTrue(SecretScope.allocations() > readBefore,
                "no secret was ever read, so this proves nothing");
    }

    /**
     * A TLS layer that is the server: each request answered as {@code server}
     * says, and one of the answers - picked at random - spoilt, or the
     * connection cut inside it.
     */
    private static final class Spoilt implements TlsLayer {

        private final Function<BsonDocument, BsonDocument> server;
        private final Random random;
        private final int spoil;
        private final List<ByteBuffer> replies = new ArrayList<>();
        private int answered;
        private int cutAt = -1;
        String what = "nothing spoilt yet";

        Spoilt(Function<BsonDocument, BsonDocument> server, Random random) {
            this.server = server;
            this.random = random;
            this.spoil = random.nextInt(3);
        }

        @Override
        public void write(ByteBuffer plain) {
            ByteBuffer in = plain.duplicate().order(ByteOrder.LITTLE_ENDIAN);
            int length = in.getInt(in.position());
            byte[] body = new byte[length - 21];
            in.position(in.position() + 21).get(body);
            byte[] reply = message(server.apply(MongoAwsTest.decode(body)));
            if (answered++ == spoil) {
                what = "reply " + spoil + ": " + mutate(reply, random);
            }
            replies.add(ByteBuffer.wrap(reply));
        }

        @Override
        public int read(ByteBuffer target) {
            if (replies.isEmpty() || cutAt == 0) {
                return -1;                           // the server has nothing more to say
            }
            ByteBuffer next = replies.get(0);
            int n = Math.min(target.remaining(), next.remaining());
            if (cutAt > 0) {
                n = Math.min(n, cutAt);
                cutAt -= n;
            }
            ByteBuffer slice = next.duplicate().limit(next.position() + n);
            target.put(slice);
            next.position(next.position() + n);
            if (!next.hasRemaining()) {
                replies.remove(0);
            }
            return n;
        }

        private String mutate(byte[] bytes, Random random) {
            switch (random.nextInt(6)) {
                case 0 -> {
                    int at = random.nextInt(bytes.length);
                    bytes[at] ^= (byte) (1 << random.nextInt(8));
                    return "bit at " + at;
                }
                case 1 -> {
                    int at = random.nextInt(bytes.length);
                    bytes[at] = (byte) random.nextInt(256);
                    return "byte at " + at;
                }
                case 2 -> {
                    // An int32 set to an edge: a message, document or binary length that lies.
                    int at = random.nextInt(Math.max(1, bytes.length - 4));
                    int[] edges = {0, -1, 4, 5, 21, Integer.MAX_VALUE, Integer.MIN_VALUE,
                        bytes.length, 48_000_001};
                    int value = edges[random.nextInt(edges.length)];
                    ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(at, value);
                    return "int32 " + value + " at " + at;
                }
                case 3 -> {
                    int n = 1 + random.nextInt(8);
                    for (int i = 0; i < n; i++) {
                        bytes[random.nextInt(bytes.length)] = (byte) random.nextInt(256);
                    }
                    return n + " bytes";
                }
                case 4 -> {
                    int at = 21 + 4 + random.nextInt(Math.max(1, bytes.length - 26));
                    if (at < bytes.length) {
                        bytes[at] = (byte) (random.nextInt(0x14)
                                + (random.nextInt(10) == 0 ? 0x70 : 0));
                    }
                    return "type byte at " + at;
                }
                default -> {
                    int before = previousBytes();
                    cutAt = before + random.nextInt(bytes.length);
                    return "cut after " + cutAt + " bytes";
                }
            }
        }

        /** What the replies before this one add up to, for a cut inside it. */
        private int previousBytes() {
            int sum = 0;
            for (ByteBuffer reply : replies) {
                sum += reply.remaining();
            }
            return sum;
        }

        @Override
        public X509Certificate peerCertificate() {
            return null;
        }

        @Override
        public String description() {
            return "spoilt";
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

    // ---- what a server answers when nothing is spoilt ----------------------------

    /**
     * SCRAM: a server-first that extends the client's nonce, then a
     * server-final whose signature cannot be right - a fuzzer has no password
     * hash - and, now and then, a refusal.
     */
    private static BsonDocument scramServer(BsonDocument request) {
        if (request.containsKey("saslStart")) {
            String clientFirst = new String(request.getBinary("payload").getData(),
                    StandardCharsets.US_ASCII);
            String nonce = clientFirst.substring(clientFirst.indexOf("r=") + 2);
            String serverFirst = "r=" + nonce + "c2VydmVybm9uY2U,s="
                    + Base64.getEncoder().encodeToString(new byte[16]) + ",i=4096";
            return sasl(serverFirst.getBytes(StandardCharsets.US_ASCII), false);
        }
        if (request.getBinary("payload").getData().length > 0) {
            return sasl(("v=" + Base64.getEncoder().encodeToString(new byte[32]))
                    .getBytes(StandardCharsets.US_ASCII), false);
        }
        return done();
    }

    /** AWS: a server nonce that extends the client's and an STS host, then done. */
    private static BsonDocument awsServer(BsonDocument request) {
        if (request.containsKey("saslStart")) {
            byte[] client = MongoAwsTest.payload(request).getBinary("r").getData();
            byte[] nonce = new byte[64];
            System.arraycopy(client, 0, nonce, 0, Math.min(32, client.length));
            for (int i = 32; i < 64; i++) {
                nonce[i] = (byte) i;
            }
            BsonDocument answer = new BsonDocument("s", new BsonBinary(nonce))
                    .append("h", new BsonString("sts.amazonaws.com"));
            return sasl(MongoAwsTest.encode(answer), false);
        }
        return done();
    }

    private static BsonDocument sasl(byte[] payload, boolean done) {
        return new BsonDocument("ok", new BsonInt32(1))
                .append("conversationId", new BsonInt32(1))
                .append("done", BsonBoolean.valueOf(done))
                .append("payload", new BsonBinary(payload));
    }

    private static BsonDocument done() {
        return sasl(new byte[0], true);
    }

    private static byte[] message(BsonDocument body) {
        byte[] bytes = MongoAwsTest.encode(body);
        ByteBuffer message = ByteBuffer.allocate(21 + bytes.length)
                .order(ByteOrder.LITTLE_ENDIAN);
        message.putInt(21 + bytes.length).putInt(99).putInt(0).putInt(2013).putInt(0)
                .put((byte) 0).put(bytes);
        return message.array();
    }
}
