package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import space.seclume.internal.Transport;

/**
 * A HelloRetryRequest is followed at most once, and only when it asks for
 * something this client offered and has not already sent: a group offered
 * without a share, or a cookie. Everything else is refused before a second
 * ClientHello goes out - or, after it, a second request or a change of suite.
 */
class HelloRetryRequestTest {

    private static final byte[] HRR_RANDOM = {
        (byte) 0xCF, (byte) 0x21, (byte) 0xAD, (byte) 0x74, (byte) 0xE5, (byte) 0x9A,
        (byte) 0x61, (byte) 0x11, (byte) 0xBE, (byte) 0x1D, (byte) 0x8C, (byte) 0x02,
        (byte) 0x1E, (byte) 0x65, (byte) 0xB8, (byte) 0x91, (byte) 0xC2, (byte) 0xA2,
        (byte) 0x11, (byte) 0x16, (byte) 0x7A, (byte) 0xBB, (byte) 0x8C, (byte) 0x5E,
        (byte) 0x07, (byte) 0x9E, (byte) 0x09, (byte) 0xE2, (byte) 0xC8, (byte) 0xA8,
        (byte) 0x33, (byte) 0x9C};

    @Test
    void aGroupThatAlreadyHadAShareIsRefused() {
        Peer peer = new Peer(id -> retry(id, 0x1301, keyShare(0x0017)));
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, refused(peer).alert());
        assertEquals(1, peer.hellos());
    }

    @Test
    void aGroupNeverOfferedIsRefused() {
        Peer peer = new Peer(id -> retry(id, 0x1301, keyShare(0x0019)));   // secp521r1
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, refused(peer).alert());
        assertEquals(1, peer.hellos());
    }

    @Test
    void aRequestThatAsksForNothingIsRefused() {
        Peer peer = new Peer(id -> retry(id, 0x1301, new byte[0]));
        TlsProtocolException refused = refused(peer);
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, refused.alert());
        assertTrue(refused.getMessage().contains("asks for nothing"), refused.getMessage());
    }

    @Test
    void aSecondRequestIsRefused() {
        Peer peer = new Peer(List.of(id -> retry(id, 0x1301, keyShare(0x0018)),
                id -> retry(id, 0x1301, keyShare(0x0018))));
        TlsProtocolException refused = refused(peer);
        assertEquals(TlsAlertException.UNEXPECTED_MESSAGE, refused.alert());
        assertEquals(2, peer.hellos(), "the P-384 request should have been followed once");
    }

    /** RFC 8446 section 4.1.4: the ServerHello keeps the suite its HelloRetryRequest named. */
    @Test
    void aChangeOfSuiteAfterTheRequestIsRefused() {
        Peer peer = new Peer(List.of(id -> retry(id, 0x1301, keyShare(0x0018)),
                id -> serverHello(id, 0x1302, 0x0018, 97)));
        TlsProtocolException refused = refused(peer);
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, refused.alert());
        assertTrue(refused.getMessage().contains("cipher suite"), refused.getMessage());
    }

    @Test
    void theSecondClientHelloCarriesTheRequestedShareAndTheCookie() {
        byte[] cookie = {1, 2, 3, 4, 5};
        Peer peer = new Peer(id -> retry(id, 0x1301, concat(keyShare(0x0018),
                extension(44, concat(new byte[] {0, (byte) cookie.length}, cookie)))));
        assertThrows(java.io.IOException.class,
                () -> ClientHandshake.connectWithoutAuthenticating(peer, "db.example.com"));
        assertEquals(2, peer.hellos());
        byte[] second = peer.hello(1);
        assertTrue(contains(second, concat(new byte[] {0, 44, 0, 7, 0, 5}, cookie)),
                "the cookie was not echoed");
        // key_share with exactly one entry: P-384, 97 bytes
        assertTrue(contains(second, new byte[] {0, 51, 0, 103, 0, 101, 0, 0x18, 0, 97, 4}),
                "the second ClientHello does not carry exactly a P-384 share");
    }

    // ---- the peer -------------------------------------------------------------

    private static TlsProtocolException refused(Peer peer) {
        return assertThrows(TlsProtocolException.class,
                () -> ClientHandshake.connectWithoutAuthenticating(peer, "db.example.com"));
    }

    /** Answers the n-th ClientHello with the n-th answer; then the line goes quiet. */
    private static final class Peer implements Transport {

        private final List<Function<byte[], byte[]>> answers;
        private final List<byte[]> hellos = new ArrayList<>();
        private ByteBuffer toClient = ByteBuffer.allocate(0);

        Peer(Function<byte[], byte[]> first) {
            this(List.of(first));
        }

        Peer(List<Function<byte[], byte[]>> answers) {
            this.answers = answers;
        }

        int hellos() {
            return hellos.size();
        }

        byte[] hello(int index) {
            return hellos.get(index);
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
            // A ClientHello record: type 22, then the handshake type 1.
            if (bytes.length > 5 && bytes[0] == 22 && bytes[5] == 1) {
                hellos.add(bytes);
                int index = hellos.size() - 1;
                if (index < answers.size()) {
                    int length = bytes[43] & 0xff;
                    byte[] answer = answers.get(index).apply(
                            Arrays.copyOfRange(bytes, 44, 44 + length));
                    ByteBuffer next = ByteBuffer.allocate(toClient.remaining() + answer.length);
                    next.put(toClient).put(answer).flip();
                    toClient = next;
                }
            }
            return n;
        }

        @Override
        public boolean isOpen() {
            return true;
        }

        @Override
        public void close() {
        }
    }

    // ---- building a HelloRetryRequest -----------------------------------------------

    private static byte[] retry(byte[] sessionId, int suite, byte[] extensions) {
        byte[] all = concat(extension(43, new byte[] {3, 4}), extensions);
        byte[] body = concat(new byte[] {3, 3}, HRR_RANDOM,
                new byte[] {(byte) sessionId.length}, sessionId,
                new byte[] {(byte) (suite >>> 8), (byte) suite, 0},
                new byte[] {(byte) (all.length >>> 8), (byte) all.length}, all);
        byte[] message = concat(new byte[] {Handshake.SERVER_HELLO, 0,
                (byte) (body.length >>> 8), (byte) body.length}, body);
        return concat(new byte[] {22, 3, 3, (byte) (message.length >>> 8), (byte) message.length},
                message);
    }

    /** A TLS 1.3 ServerHello with a key share of {@code shareLength} bytes for {@code group}. */
    private static byte[] serverHello(byte[] sessionId, int suite, int group, int shareLength) {
        byte[] share = new byte[shareLength];
        share[0] = 4;
        byte[] keyShare = extension(51, concat(new byte[] {(byte) (group >>> 8), (byte) group,
                (byte) (shareLength >>> 8), (byte) shareLength}, share));
        byte[] all = concat(extension(43, new byte[] {3, 4}), keyShare);
        byte[] random = new byte[32];
        Arrays.fill(random, (byte) 0x33);
        byte[] body = concat(new byte[] {3, 3}, random,
                new byte[] {(byte) sessionId.length}, sessionId,
                new byte[] {(byte) (suite >>> 8), (byte) suite, 0},
                new byte[] {(byte) (all.length >>> 8), (byte) all.length}, all);
        byte[] message = concat(new byte[] {Handshake.SERVER_HELLO, 0,
                (byte) (body.length >>> 8), (byte) body.length}, body);
        return concat(new byte[] {22, 3, 3, (byte) (message.length >>> 8), (byte) message.length},
                message);
    }

    private static byte[] keyShare(int group) {
        return extension(51, new byte[] {(byte) (group >>> 8), (byte) group});
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

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
