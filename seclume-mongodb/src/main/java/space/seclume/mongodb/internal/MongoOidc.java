package space.seclume.mongodb.internal;

import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLException;

import space.seclume.internal.TlsLayer;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * MONGODB-OIDC, the machine workflow (auth specification, "MONGODB-OIDC"): an
 * access token from the workload's identity provider sent in one
 * {@code saslStart} - {@code {jwt: token}} - and the server checks it against
 * the provider it trusts. Atlas and Enterprise only.
 *
 * <p>The token is a bearer credential: whoever holds it is the workload until
 * it expires. So it is read from its provider into native memory, written
 * into the payload from there, and both are wiped once sent - it never
 * becomes a String. A token file (a Kubernetes service account's, say) is
 * read again for every login, so a rotated token is taken up by the next
 * connection, and by a connection the server asks to log in again
 * (ReauthenticationRequired, 391).
 */
public final class MongoOidc {

    public static final String MECHANISM = "MONGODB-OIDC";
    /** Where Kubernetes mounts a service account's token. */
    public static final String KUBERNETES_TOKEN =
            "/var/run/secrets/kubernetes.io/serviceaccount/token";
    private static final int OP_MSG = 2013;
    private static final int MAX_TOKEN = 16 * 1024;
    private static final AtomicInteger REQUEST_IDS = new AtomicInteger(1 << 21);

    private MongoOidc() {
    }

    public static void authenticate(TlsLayer tls, SecretProvider token, String host, int port)
            throws IOException {
        try {
            login(tls, token, host, port);
        } catch (BsonReader.Malformed e) {
            throw MongoHandshake.malformed(host, port, e);
        }
    }

    private static void login(TlsLayer tls, SecretProvider token, String host, int port)
            throws IOException {
        try (Arena arena = Arena.ofConfined();
             SecretScope jwt = SecretScope.fromProvider(token)) {
            if (jwt.length() == 0 || jwt.length() > MAX_TOKEN) {
                throw new SSLException("the OIDC token is " + jwt.length() + " bytes; between 1 "
                        + "and " + MAX_TOKEN + " are taken");
            }
            for (long i = 0; i < jwt.length(); i++) {
                byte b = jwt.segment().get(ValueLayout.JAVA_BYTE, i);
                if (b <= ' ' || b >= 0x7F) {
                    // A JWT is base64url and dots; a newline at the end of a
                    // token file is the usual reason for a byte outside them.
                    throw new SSLException("the OIDC token holds a byte that is not part of a "
                            + "JWT at " + i + " - is there a line break in the token file?");
                }
            }
            MemorySegment payload = arena.allocate(64 + jwt.length());
            MemorySegment command = arena.allocate(512 + jwt.length());
            try {
                BsonWriter inner = new BsonWriter(payload, 0);
                inner.putString("jwt", jwt.segment(), jwt.length());
                int innerLength = inner.finish();
                BsonWriter outer = new BsonWriter(command, 21);
                outer.putInt32("saslStart", 1);
                outer.putString("mechanism", MECHANISM);
                outer.putBinary("payload", payload, 0, innerLength);
                outer.putString("$db", "$external");
                send(tls, command, outer.finish());
            } finally {
                payload.fill((byte) 0);
                command.fill((byte) 0);
            }
            BsonReader reply = read(tls, arena);
            if (!reply.isOk()) {
                String error = reply.errmsg();
                throw new SSLException("the server at " + host + ":" + port + " refused the "
                        + "OIDC token: " + (error != null ? error : "code " + reply.code()));
            }
            if (!reply.isDone()) {
                throw new SSLException("the MONGODB-OIDC login did not end after its one step");
            }
        }
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
            throw new SSLException("not an OP_MSG of a sane length during the OIDC login");
        }
        MemorySegment body = arena.allocate(length - 16);
        fill(tls, body.asByteBuffer());
        if (body.get(ValueLayout.JAVA_BYTE, 4) != 0) {
            throw new SSLException("an OP_MSG without a body section during the OIDC login");
        }
        return new BsonReader(body, 5);
    }

    private static void fill(TlsLayer tls, ByteBuffer into) throws IOException {
        while (into.hasRemaining()) {
            if (tls.read(into) < 0) {
                throw new EOFException("the connection ended during the MONGODB-OIDC login");
            }
        }
    }
}
