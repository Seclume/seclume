package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.function.Function;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.Transport;

/**
 * {@code -Dseclume.tls.requireExtendedMasterSecret=false}: a TLS 1.2 server
 * without the extended master secret is let through only when that is said by
 * name, and refused otherwise. Isolated: it changes a system property.
 */
@Isolated
class Tls12WithoutExtendedMasterSecretTest {

    private static final String PROPERTY = "seclume.tls.requireExtendedMasterSecret";

    @Test
    void refusedByDefaultAndLetThroughByName() {
        Function<byte[], byte[]> withoutEms = id -> serverHello(0x0303, plainRandom(), 0xC02F,
                renegotiationInfo());
        TlsProtocolException refused = assertThrows(TlsProtocolException.class,
                () -> ClientHandshake.connectWithoutAuthenticating(new Peer(withoutEms),
                        "db.example.com"));
        assertEquals(TlsAlertException.HANDSHAKE_FAILURE, refused.alert());
        assertTrue(refused.getMessage().contains(PROPERTY), refused.getMessage());

        System.setProperty(PROPERTY, "false");
        try {
            IOException gone = assertThrows(IOException.class,
                    () -> ClientHandshake.connectWithoutAuthenticating(new Peer(withoutEms),
                            "db.example.com"));
            // Past the ServerHello: the server's flight simply ends here.
            assertInstanceOf(EOFException.class, gone, gone.toString());
        } finally {
            System.clearProperty(PROPERTY);
        }
    }

    // ---- the peer -----------------------------------------------------------

    private static TlsProtocolException refused(Peer peer) {
        return assertThrows(TlsProtocolException.class,
                () -> ClientHandshake.connectWithoutAuthenticating(peer, "db.example.com"));
    }

    /** Answers the ClientHello with whatever {@code answer} builds from its session id. */
    private static final class Peer implements Transport {

        private final Function<byte[], byte[]> answer;
        private final ByteArrayOutputStream written = new ByteArrayOutputStream();
        private ByteBuffer toClient = ByteBuffer.allocate(0);
        private boolean answered;

        Peer(Function<byte[], byte[]> answer) {
            this.answer = answer;
        }

        @Override
        public int read(ByteBuffer into) {
            if (!toClient.hasRemaining()) {
                return -1;
            }
            int n = Math.min(into.remaining(), toClient.remaining());
            ByteBuffer slice = toClient.slice().limit(n);
            into.put(slice);
            toClient.position(toClient.position() + n);
            return n;
        }

        @Override
        public int write(ByteBuffer from) {
            int n = from.remaining();
            byte[] bytes = new byte[n];
            from.get(bytes);
            written.writeBytes(bytes);
            if (!answered) {
                answered = true;
                byte[] hello = written.toByteArray();
                int length = hello[43] & 0xff;
                toClient = ByteBuffer.wrap(answer.apply(Arrays.copyOfRange(hello, 44, 44 + length)));
            }
            return n;
        }

        /** The alert the client sent last, or -1. */
        int alertSent() {
            byte[] all = written.toByteArray();
            int at = 0;
            int alert = -1;
            while (all.length - at >= 5) {
                int type = all[at] & 0xff;
                int length = ((all[at + 3] & 0xff) << 8) | (all[at + 4] & 0xff);
                if (type == 21 && length >= 2 && at + 6 < all.length) {
                    alert = all[at + 6] & 0xff;
                }
                at += 5 + length;
            }
            return alert;
        }

        @Override
        public boolean isOpen() {
            return true;
        }

        @Override
        public void close() {
        }
    }

    // ---- building a ServerHello -------------------------------------------------

    private static byte[] plainRandom() {
        byte[] random = new byte[32];
        Arrays.fill(random, (byte) 0x11);
        return random;
    }

    private static byte[] renegotiationInfo() {
        return extension(0xff01, new byte[] {0});
    }

    private static byte[] extension(int type, byte[] body) {
        byte[] out = new byte[4 + body.length];
        out[0] = (byte) (type >>> 8);
        out[1] = (byte) type;
        out[2] = (byte) (body.length >>> 8);
        out[3] = (byte) body.length;
        System.arraycopy(body, 0, out, 4, body.length);
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    /** A plaintext handshake record carrying one ServerHello; a TLS 1.2 one gets a fresh id. */
    private static byte[] serverHello(int version, byte[] random, int suite, byte[] extensions) {
        byte[] sessionId = new byte[32];
        Arrays.fill(sessionId, (byte) 0x22);
        byte[] body = concat(new byte[] {(byte) (version >>> 8), (byte) version}, random,
                new byte[] {(byte) sessionId.length}, sessionId,
                new byte[] {(byte) (suite >>> 8), (byte) suite, 0},
                extensions.length == 0 ? new byte[0]
                        : concat(new byte[] {(byte) (extensions.length >>> 8),
                                (byte) extensions.length}, extensions));
        byte[] message = concat(new byte[] {Handshake.SERVER_HELLO, 0,
                (byte) (body.length >>> 8), (byte) body.length}, body);
        return concat(new byte[] {22, 3, 3, (byte) (message.length >>> 8), (byte) message.length},
                message);
    }
}
