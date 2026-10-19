package space.seclume.mongodb.internal;

import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLException;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.internal.Scram;
import space.seclume.internal.TlsLayer;
import space.seclume.mongodb.MongoUrl;
import space.seclume.secret.SecretScope;

/**
 * Logs the connection in with SCRAM-SHA-256 over TLS before the connection is
 * handed to the MongoDB driver.
 *
 * <p>There is no {@code hello} of our own first. The server takes client
 * metadata only in the first {@code hello} of a connection and answers a
 * second one that carries it with error 186 (ClientMetadataCannotBeMutated) -
 * and the driver's own {@code hello}, which follows on the connection this
 * hands over, always carries it. {@code saslStart} needs no {@code hello}
 * before it, and a mechanism the server does not offer for the user is
 * refused right there, which is where the check against SCRAM-SHA-1 or
 * anything weaker happens.
 *
 * <p>All secret calculations - password, PBKDF2 derivation, client key, proof
 * and server signature verification - run in native memory through
 * {@link Scram} and are zeroed immediately upon completion.
 */
public final class MongoHandshake {

    private static final int OP_MSG = 2013;
    private static final int MAX_BSON_SIZE = 48 * 1024 * 1024;
    private static final int MIN_ITERATIONS = 4096;
    private static final int MAX_ITERATIONS = 10_000_000;
    private static final AtomicInteger REQUEST_IDS = new AtomicInteger();

    private MongoHandshake() {
    }

    /**
     * Authenticates the connection using SCRAM-SHA-256.
     */
    public static void authenticate(TlsLayer tls, MongoUrl url, String host, int port)
            throws IOException {
        try {
            scram(tls, url, host, port);
        } catch (BsonReader.Malformed e) {
            throw malformed(host, port, e);
        }
    }

    /** A reply that is not BSON: the login failed, as any other refusal by the server. */
    static SSLException malformed(String host, int port, BsonReader.Malformed e) {
        return new SSLException("MongoDB login on " + host + ":" + port + " failed: a reply "
                + "that is not well-formed BSON: " + e.getMessage(), e);
    }

    private static void scram(TlsLayer tls, MongoUrl url, String host, int port)
            throws IOException {
        String user = url.user();
        String authSource = url.authSource();

        try (Arena arena = Arena.ofConfined();
             Scram scram = new Scram(HashAlgorithm.SHA_256, 24)) {

            // Step 1: saslStart
            MemorySegment clientFirst = arena.allocate(512);
            int clientFirstLen = scram.clientFirst(clientFirst, user);

            MemorySegment msg1 = arena.allocate(1024 + clientFirstLen);
            BsonWriter writer1 = new BsonWriter(msg1, 21);
            writer1.putInt32("saslStart", 1);
            writer1.putString("mechanism", "SCRAM-SHA-256");
            writer1.putBinary("payload", clientFirst, 0, clientFirstLen);
            writer1.putInt32("autoAuthorize", 1);
            writer1.putString("$db", authSource);
            int docLen1 = writer1.finish();
            sendOpMsg(tls, msg1, docLen1);

            BsonReader reply1 = readOpMsg(tls, arena);
            if (!reply1.isOk()) {
                String error = reply1.errmsg();
                throw new SSLException("MongoDB login failed for user '" + user + "' on "
                        + host + ":" + port + ": the server refused SCRAM-SHA-256 for this user"
                        + " (only SCRAM-SHA-256 is used, never SCRAM-SHA-1): "
                        + (error != null ? error : "code " + reply1.code()));
            }

            int conversationId = reply1.conversationId();
            MemorySegment serverFirst = reply1.getBinary("payload");
            if (serverFirst == null) {
                throw new SSLException("MongoDB saslStart reply is missing binary payload for user '"
                        + user + "' on " + host + ":" + port);
            }

            try {
                scram.serverFirst(serverFirst, 0, (int) serverFirst.byteSize());
            } catch (IllegalStateException | IllegalArgumentException e) {
                throw new SSLException("MongoDB server-first validation failed for user '" + user
                        + "' on " + host + ":" + port + ": " + e.getMessage(), e);
            }

            int iterations = scram.iterations();
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                throw new SSLException("MongoDB login failed for user '" + user + "' on "
                        + host + ":" + port + ": server requested " + iterations
                        + " iterations; expected between " + MIN_ITERATIONS + " and " + MAX_ITERATIONS);
            }

            // Step 2: saslContinue. The client-final message carries the
            // proof; it and the command built around it are zeroed once
            // sent - closing an arena frees its memory but does not wipe it.
            MemorySegment clientFinal = arena.allocate(1024);
            MemorySegment msg2 = null;
            int clientFinalLen;
            try {
                try (SecretScope password = SecretScope.fromProvider(url.secret())) {
                    MemorySegment passSeg = password.segment();
                    long passLen = password.length();
                    // Enforce SASLprep ASCII-only invariant
                    for (long i = 0; i < passLen; i++) {
                        byte b = passSeg.get(ValueLayout.JAVA_BYTE, i);
                        if (b < 0x20 || b >= 0x7F) {
                            throw new IllegalArgumentException("MongoDB login failed for user '" + user
                                    + "' on " + host + ":" + port
                                    + ": password contains non-ASCII characters; SASLprep is required by MongoDB but refused in v1");
                        }
                    }
                    clientFinalLen = scram.clientFinal(clientFinal, passSeg.asSlice(0, passLen));
                } // password scope closed and wiped immediately here!

                msg2 = arena.allocate(1024 + clientFinalLen);
                BsonWriter writer2 = new BsonWriter(msg2, 21);
                writer2.putInt32("saslContinue", 1);
                writer2.putInt32("conversationId", conversationId);
                writer2.putBinary("payload", clientFinal, 0, clientFinalLen);
                writer2.putString("$db", authSource);
                int docLen2 = writer2.finish();
                sendOpMsg(tls, msg2, docLen2);
            } finally {
                clientFinal.fill((byte) 0);
                if (msg2 != null) {
                    msg2.fill((byte) 0);
                }
            }

            BsonReader reply2 = readOpMsg(tls, arena);
            if (!reply2.isOk()) {
                String error = reply2.errmsg();
                throw new SSLException("MongoDB saslContinue failed for user '" + user + "' on "
                        + host + ":" + port + ": " + (error != null ? error : "code " + reply2.code()));
            }

            MemorySegment serverFinal = reply2.getBinary("payload");
            if (serverFinal == null) {
                throw new SSLException("MongoDB saslContinue reply is missing binary payload for user '"
                        + user + "' on " + host + ":" + port);
            }

            try {
                scram.verifyServerFinal(serverFinal, 0, (int) serverFinal.byteSize());
            } catch (Exception e) {
                throw new SSLException("MongoDB login failed for user '" + user + "' on "
                        + host + ":" + port + ": mutual authentication failed: " + e.getMessage(), e);
            }

            // If not marked done yet, send one final empty saslContinue to complete
            if (!reply2.isDone()) {
                MemorySegment msg3 = arena.allocate(512);
                BsonWriter writer3 = new BsonWriter(msg3, 21);
                writer3.putInt32("saslContinue", 1);
                writer3.putInt32("conversationId", conversationId);
                writer3.putBinary("payload", arena.allocate(0), 0, 0);
                writer3.putString("$db", authSource);
                int docLen3 = writer3.finish();
                sendOpMsg(tls, msg3, docLen3);

                BsonReader reply3 = readOpMsg(tls, arena);
                if (!reply3.isOk() || !reply3.isDone()) {
                    String error = reply3.errmsg();
                    throw new SSLException("MongoDB saslContinue final completion failed for user '"
                            + user + "' on " + host + ":" + port + ": "
                            + (error != null ? error : "not marked done"));
                }
            }
        }
    }

    private static void sendOpMsg(TlsLayer tls, MemorySegment msg, int docLength)
            throws IOException {
        int totalLength = 21 + docLength;
        int reqId = REQUEST_IDS.incrementAndGet();

        // 16-byte OP_MSG Header
        msg.set(ValueLayout.JAVA_INT_UNALIGNED, 0, totalLength);
        msg.set(ValueLayout.JAVA_INT_UNALIGNED, 4, reqId);
        msg.set(ValueLayout.JAVA_INT_UNALIGNED, 8, 0);       // responseTo
        msg.set(ValueLayout.JAVA_INT_UNALIGNED, 12, OP_MSG); // opCode = 2013

        // 4-byte flagBits = 0
        msg.set(ValueLayout.JAVA_INT_UNALIGNED, 16, 0);

        // 1-byte section type 0 (Body)
        msg.set(ValueLayout.JAVA_BYTE, 20, (byte) 0);

        tls.write(msg.asSlice(0, totalLength).asByteBuffer());
    }

    private static BsonReader readOpMsg(TlsLayer tls, Arena arena) throws IOException {
        MemorySegment header = arena.allocate(16);
        readExact(tls, header.asByteBuffer());

        int messageLength = header.get(ValueLayout.JAVA_INT_UNALIGNED, 0);
        int opCode = header.get(ValueLayout.JAVA_INT_UNALIGNED, 12);
        if (opCode != OP_MSG) {
            throw new SSLException("expected OP_MSG (" + OP_MSG + "), received opCode " + opCode);
        }
        if (messageLength < 21 || messageLength > MAX_BSON_SIZE) {
            throw new SSLException("invalid OP_MSG message length: " + messageLength);
        }

        int remaining = messageLength - 16;
        MemorySegment body = arena.allocate(remaining);
        readExact(tls, body.asByteBuffer());

        int flagBits = body.get(ValueLayout.JAVA_INT_UNALIGNED, 0);
        if ((flagBits & 1) != 0) {
            throw new SSLException("checksumPresent in OP_MSG during login is not supported");
        }

        byte sectionType = body.get(ValueLayout.JAVA_BYTE, 4);
        if (sectionType != 0) {
            throw new SSLException("expected OP_MSG section type 0 (body), received " + sectionType);
        }

        // BSON document begins at offset 5 in body
        return new BsonReader(body, 5);
    }

    private static void readExact(TlsLayer tls, ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            int n = tls.read(buf);
            if (n < 0) {
                throw new EOFException("connection closed prematurely during MongoDB authentication");
            }
        }
    }
}
