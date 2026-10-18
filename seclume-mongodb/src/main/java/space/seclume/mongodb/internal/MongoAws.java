package space.seclume.mongodb.internal;

import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLException;

import space.seclume.internal.AwsSigV4;
import space.seclume.internal.CanonicalRequest;
import space.seclume.internal.Entropy;
import space.seclume.internal.TlsLayer;
import space.seclume.secret.AwsInstanceRole;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * MONGODB-AWS: the login with AWS credentials, as MongoDB Atlas and Enterprise
 * take it (auth specification, "MONGODB-AWS"). The client proves it holds the
 * credentials by signing an STS {@code GetCallerIdentity} request that the
 * server sends on to AWS; nothing of the key goes to the server, only the
 * signature - and the session token, which AWS needs to check it.
 *
 * <p>Two SASL steps. The client sends a 32-byte nonce; the server answers with
 * 64 bytes that begin with it and the STS host to address. The client signs a
 * POST of {@code Action=GetCallerIdentity&Version=2011-06-15} to that host
 * with SigV4, the server nonce and the channel binding flag among the signed
 * headers, and sends the Authorization header, the date and the session token.
 *
 * <p>Off the heap, as everything else here: the secret key goes into the
 * signing chain from native memory ({@link AwsSigV4}); the session token goes
 * into the canonical request ({@link CanonicalRequest#secret}) and into the
 * payload straight from native memory too, and every segment that held it is
 * wiped before this returns. What becomes a String is public - the access key
 * id, the date, the host, the signature.
 */
public final class MongoAws {

    public static final String MECHANISM = "MONGODB-AWS";
    private static final int OP_MSG = 2013;
    private static final int NONCE = 32;
    private static final String BODY = "Action=GetCallerIdentity&Version=2011-06-15";
    private static final String BODY_SHA256 = AwsSigV4.sha256Hex(BODY);
    private static final int MAX_TOKEN = 8192;
    private static final AtomicInteger REQUEST_IDS = new AtomicInteger(1 << 20);
    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DAY =
            DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);

    /** Where the credentials come from: the workload's role, or a key pair from providers. */
    public record Credentials(AwsInstanceRole role, String accessKeyId, SecretProvider secretKey,
                              SecretProvider sessionToken) {

        <T> T use(AwsInstanceRole.Use<T> use) {
            return role != null ? role.use(use) : use.with(accessKeyId, secretKey, sessionToken);
        }
    }

    private MongoAws() {
    }

    public static void authenticate(TlsLayer tls, Credentials credentials, String host, int port)
            throws IOException {
        authenticate(tls, credentials, host, port, Clock.systemUTC());
    }

    static void authenticate(TlsLayer tls, Credentials credentials, String host, int port,
            Clock clock) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment clientNonce = arena.allocate(NONCE);
            Entropy.fill(clientNonce);

            // ---- saslStart: {r: nonce, p: 'n'} ----
            MemorySegment first = arena.allocate(128);
            BsonWriter firstPayload = new BsonWriter(first, 0);
            firstPayload.putBinary("r", clientNonce, 0, NONCE);
            firstPayload.putInt32("p", 'n');
            int firstLength = firstPayload.finish();
            MemorySegment start = arena.allocate(512);
            BsonWriter startCommand = new BsonWriter(start, 21);
            startCommand.putInt32("saslStart", 1);
            startCommand.putString("mechanism", MECHANISM);
            startCommand.putBinary("payload", first, 0, firstLength);
            startCommand.putString("$db", "$external");
            send(tls, start, startCommand.finish());

            BsonReader started = read(tls, arena);
            if (!started.isOk()) {
                throw new SSLException("the server at " + host + ":" + port + " refused "
                        + MECHANISM + ": " + reason(started));
            }
            int conversationId = started.conversationId();
            MemorySegment serverPayload = started.getBinary("payload");
            if (serverPayload == null) {
                throw new SSLException("the server's MONGODB-AWS answer has no payload");
            }
            BsonReader server = new BsonReader(serverPayload, 0);
            MemorySegment serverNonce = server.getBinary("s");
            String stsHost = server.getString("h");
            check(clientNonce, serverNonce, stsHost);

            // ---- saslContinue: {a: authorization, d: date, t: session token} ----
            String date = STAMP.format(clock.instant());
            String day = DAY.format(clock.instant());
            String region = region(stsHost);
            String nonce64 = Base64.getEncoder().encodeToString(serverNonce.toArray( // seclume-allow: the server's nonce, public
                    ValueLayout.JAVA_BYTE));
            credentials.use((accessKeyId, secretKey, sessionToken) -> {
                try {
                    sign(tls, arena, conversationId, accessKeyId, secretKey, sessionToken,
                            stsHost, region, date, day, nonce64);
                } catch (IOException e) {
                    throw new java.io.UncheckedIOException(e);
                }
                return null;
            });

            BsonReader done = read(tls, arena);
            if (!done.isOk()) {
                throw new SSLException("the server at " + host + ":" + port + " refused the "
                        + "AWS credentials (STS GetCallerIdentity): " + reason(done));
            }
            if (!done.isDone()) {
                throw new SSLException("the MONGODB-AWS conversation did not end after its "
                        + "second step");
            }
        } catch (java.io.UncheckedIOException e) {
            throw e.getCause();
        }
    }

    private static void sign(TlsLayer tls, Arena arena, int conversationId, String accessKeyId,
            SecretProvider secretKey, SecretProvider sessionToken, String stsHost, String region,
            String date, String day, String nonce64) throws IOException {
        try (SecretScope token = sessionToken == null ? null
                : SecretScope.fromProvider(sessionToken);
             CanonicalRequest canonical = new CanonicalRequest(arena, 4096 + MAX_TOKEN)) {
            boolean withToken = token != null && token.length() > 0;
            if (withToken && token.length() > MAX_TOKEN) {
                throw new SSLException("the AWS session token is " + token.length()
                        + " bytes; at most " + MAX_TOKEN + " are taken");
            }
            String signedHeaders = "content-length;content-type;host;x-amz-date;"
                    + (withToken ? "x-amz-security-token;" : "")
                    + "x-mongodb-gs2-cb-flag;x-mongodb-server-nonce";
            canonical.text("POST\n/\n\n")
                    .text("content-length:" + BODY.length() + "\n")
                    .text("content-type:application/x-www-form-urlencoded\n")
                    .text("host:" + stsHost + "\n")
                    .text("x-amz-date:" + date + "\n");
            if (withToken) {
                canonical.text("x-amz-security-token:").secret(token.segment(), token.length())
                        .text("\n");
            }
            canonical.text("x-mongodb-gs2-cb-flag:n\n")
                    .text("x-mongodb-server-nonce:" + nonce64 + "\n\n")
                    .text(signedHeaders + "\n")
                    .text(BODY_SHA256);
            String scope = AwsSigV4.scope(day, region, "sts");
            String toSign = AwsSigV4.ALGORITHM + "\n" + date + "\n" + scope + "\n"
                    + canonical.sha256Hex();
            MemorySegment signature = AwsSigV4.sign(arena, target -> {
                try (SecretScope key = SecretScope.fromProvider(secretKey)) {
                    if (key.length() > target.byteSize()) {
                        throw new IllegalStateException("the AWS secret key is too long");
                    }
                    MemorySegment.copy(key.segment(), 0, target, 0, key.length());
                    return key.length();
                }
            }, toSign, day, region, "sts");
            String authorization = AwsSigV4.ALGORITHM + " Credential=" + accessKeyId + "/"
                    + scope + ", SignedHeaders=" + signedHeaders + ", Signature="
                    + AwsSigV4.hex(signature);

            MemorySegment payload = arena.allocate(1024 + MAX_TOKEN);
            MemorySegment command = arena.allocate(2048 + MAX_TOKEN);
            try {
                BsonWriter inner = new BsonWriter(payload, 0);
                inner.putString("a", authorization);
                inner.putString("d", date);
                if (withToken) {
                    inner.putString("t", token.segment(), token.length());
                }
                int innerLength = inner.finish();
                BsonWriter outer = new BsonWriter(command, 21);
                outer.putInt32("saslContinue", 1);
                outer.putInt32("conversationId", conversationId);
                outer.putBinary("payload", payload, 0, innerLength);
                outer.putString("$db", "$external");
                send(tls, command, outer.finish());
            } finally {
                payload.fill((byte) 0);
                command.fill((byte) 0);
            }
        }
    }

    /**
     * The server nonce has to begin with ours and be 64 bytes; the STS host
     * has to be a host name - it is where the server sends the signed
     * request, and the spec bounds it so that a server cannot make the client
     * sign for anything else.
     */
    static void check(MemorySegment clientNonce, MemorySegment serverNonce, String stsHost)
            throws SSLException {
        if (serverNonce == null || serverNonce.byteSize() != 2L * NONCE) {
            throw new SSLException("the server's MONGODB-AWS nonce is not 64 bytes");
        }
        if (serverNonce.asSlice(0, NONCE).mismatch(clientNonce) != -1) {
            throw new SSLException("the server's MONGODB-AWS nonce does not begin with ours");
        }
        if (stsHost == null || stsHost.isEmpty() || stsHost.length() > 255
                || stsHost.startsWith(".") || stsHost.endsWith(".") || stsHost.contains("..")) {
            throw new SSLException("the server named an STS host that is not a host name: "
                    + stsHost);
        }
    }

    /** {@code sts.amazonaws.com} is us-east-1; {@code sts.<region>.amazonaws.com} names one. */
    static String region(String stsHost) {
        String[] labels = stsHost.toLowerCase(Locale.ROOT).split("\\.");
        if (labels.length == 1 || stsHost.equalsIgnoreCase("sts.amazonaws.com")) {
            return "us-east-1";
        }
        return labels[1];
    }

    private static String reason(BsonReader reply) {
        String error = reply.errmsg();
        return error != null ? error : "code " + reply.code();
    }

    private static void send(TlsLayer tls, MemorySegment message, int documentLength)
            throws IOException {
        int total = 21 + documentLength;
        message.set(ValueLayout.JAVA_INT_UNALIGNED, 0, total);
        message.set(ValueLayout.JAVA_INT_UNALIGNED, 4, REQUEST_IDS.incrementAndGet());
        message.set(ValueLayout.JAVA_INT_UNALIGNED, 8, 0);
        message.set(ValueLayout.JAVA_INT_UNALIGNED, 12, OP_MSG);
        message.set(ValueLayout.JAVA_INT_UNALIGNED, 16, 0);
        message.set(ValueLayout.JAVA_BYTE, 20, (byte) 0);
        tls.write(message.asSlice(0, total).asByteBuffer());
    }

    private static BsonReader read(TlsLayer tls, Arena arena) throws IOException {
        MemorySegment header = arena.allocate(16);
        fill(tls, header.asByteBuffer());
        int length = header.get(ValueLayout.JAVA_INT_UNALIGNED, 0);
        if (header.get(ValueLayout.JAVA_INT_UNALIGNED, 12) != OP_MSG || length < 21
                || length > 48 * 1024 * 1024) {
            throw new SSLException("not an OP_MSG of a sane length during the AWS login");
        }
        MemorySegment body = arena.allocate(length - 16);
        fill(tls, body.asByteBuffer());
        if (body.get(ValueLayout.JAVA_BYTE, 4) != 0) {
            throw new SSLException("an OP_MSG without a body section during the AWS login");
        }
        return new BsonReader(body, 5);
    }

    private static void fill(TlsLayer tls, ByteBuffer into) throws IOException {
        while (into.hasRemaining()) {
            if (tls.read(into) < 0) {
                throw new EOFException("the connection ended during the MONGODB-AWS login");
            }
        }
    }
}
