package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.function.Function;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.Transport;

/**
 * A ServerHello that is shaped wrong, answered by an unauthenticated peer -
 * anybody on the path - before any key exists. The audit of 27.09.2026 found
 * duplicate extensions accepted, a key share read past the end of its own
 * extension, and a short message escaping as IndexOutOfBoundsException. Each
 * must now end the handshake as TLS says: with an alert and a
 * {@link TlsProtocolException}.
 */
@Timeout(30)
class ServerHelloStrictnessTest {

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
                // record header 5, handshake header 4, version 2, random 32:
                // the session id's length byte, then the id.
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
                int description = at + 6;          // level at at + 5, description after it
                if (type == 21 && length >= 2 && description < all.length) {
                    alert = all[description] & 0xff;
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

    private static byte[] extension(int type, byte[] body) {
        byte[] out = new byte[4 + body.length];
        out[0] = (byte) (type >>> 8);
        out[1] = (byte) type;
        out[2] = (byte) (body.length >>> 8);
        out[3] = (byte) body.length;
        System.arraycopy(body, 0, out, 4, body.length);
        return out;
    }

    private static byte[] supportedVersions() {
        return extension(Handshake.EXTENSION_SUPPORTED_VERSIONS, new byte[] {3, 4});
    }

    /** A P-256 key share: group, length 65, an uncompressed point. */
    private static byte[] p256Share() {
        byte[] body = new byte[4 + 65];
        body[1] = 0x17;
        body[3] = 65;
        body[4] = 4;
        return extension(Handshake.EXTENSION_KEY_SHARE, body);
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    /** A plaintext handshake record carrying one ServerHello with {@code extensions}. */
    private static byte[] serverHello(byte[] sessionId, byte[] extensions, boolean cutAfterId) {
        byte[] random = new byte[32];
        Arrays.fill(random, (byte) 0x11);
        byte[] body = cutAfterId
                ? concat(new byte[] {3, 3}, random, new byte[] {(byte) sessionId.length}, sessionId)
                : concat(new byte[] {3, 3}, random, new byte[] {(byte) sessionId.length}, sessionId,
                        new byte[] {0x13, 0x01, 0},
                        new byte[] {(byte) (extensions.length >>> 8), (byte) extensions.length},
                        extensions);
        byte[] message = concat(new byte[] {Handshake.SERVER_HELLO, 0,
                (byte) (body.length >>> 8), (byte) body.length}, body);
        return concat(new byte[] {22, 3, 3, (byte) (message.length >>> 8), (byte) message.length},
                message);
    }

    private static TlsProtocolException refused(Peer peer) {
        return assertThrows(TlsProtocolException.class,
                () -> ClientHandshake.connectWithoutAuthenticating(peer, "db.example.com"));
    }

    @Test
    void aRepeatedKeyShareIsRefused() {
        Peer peer = new Peer(id -> serverHello(id,
                concat(supportedVersions(), p256Share(), p256Share()), false));
        TlsProtocolException refused = refused(peer);
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, refused.alert());
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, peer.alertSent());
    }

    @Test
    void aRepeatedSupportedVersionsIsRefused() {
        Peer peer = new Peer(id -> serverHello(id,
                concat(supportedVersions(), supportedVersions(), p256Share()), false));
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, refused(peer).alert());
    }

    /**
     * The key share announces 65 bytes and its extension holds none: the
     * share used to be read from whatever followed the extension.
     */
    @Test
    void aKeyShareLongerThanItsExtensionIsRefused() {
        byte[] shortShare = extension(Handshake.EXTENSION_KEY_SHARE, new byte[] {0, 0x17, 0, 65});
        byte[] padding = extension(0x7a7a, new byte[70]);
        Peer peer = new Peer(id -> serverHello(id,
                concat(supportedVersions(), shortShare, padding), false));
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, refused(peer).alert());
    }

    @Test
    void aServerHelloThatEndsAfterTheSessionIdIsADecodeError() {
        Peer peer = new Peer(id -> serverHello(id, new byte[0], true));
        TlsProtocolException refused = refused(peer);
        assertEquals(TlsAlertException.DECODE_ERROR, refused.alert());
        assertTrue(refused.getCause() instanceof IndexOutOfBoundsException, "cause kept");
        assertEquals(TlsAlertException.DECODE_ERROR, peer.alertSent());
    }

    /**
     * Well shaped, but the point is not on the curve: refused at the key
     * exchange - as illegal_parameter, not as an unchecked exception out of
     * the login path.
     */
    @Test
    void aKeyShareOffTheCurveIsAnIllegalParameter() {
        Peer peer = new Peer(id -> serverHello(id, concat(supportedVersions(), p256Share()),
                false));
        TlsProtocolException refused = refused(peer);
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, refused.alert());
        assertTrue(refused.getMessage().contains("key share was refused"), refused.getMessage());
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, peer.alertSent());
    }

    // ---- found by TLS-Anvil, 27.09.2026 -----------------------------------

    /** Byte {@code at} of the record changed to {@code value}. */
    private static byte[] with(byte[] record, int at, int value) {
        byte[] changed = record.clone();
        changed[at] = (byte) value;
        return changed;
    }

    /** record header 5, handshake header 4, version 2, random 32, id 1 + 32, suite 2. */
    private static final int COMPRESSION = 5 + 4 + 2 + 32 + 1 + 32 + 2;

    @Test
    void aCompressionMethodIsRefused() {
        Peer peer = new Peer(id -> with(serverHello(id,
                concat(supportedVersions(), p256Share()), false), COMPRESSION, 1));
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, refused(peer).alert());
    }

    /**
     * RFC 8446 section 4.2.1: with supported_versions present, the client
     * MUST ignore legacy_version. This one used to refuse 0x0304 there with
     * protocol_version (TLS-Anvil 8446-oysw9PbeiT, 28.09.2026). Ignored now:
     * the handshake goes on to the key share - off the curve in this test
     * server's answer, which is where it stops.
     */
    @Test
    void aWrongLegacyVersionIsIgnoredWhenSupportedVersionsSaysThirteen() {
        for (int[] version : new int[][] {{3, 4}, {5, 5}}) {
            Peer peer = new Peer(id -> with(with(serverHello(id,
                    concat(supportedVersions(), p256Share()), false),
                    5 + 4, version[0]), 5 + 4 + 1, version[1]));
            TlsProtocolException refused = refused(peer);
            assertEquals(TlsAlertException.ILLEGAL_PARAMETER, refused.alert(),
                    refused.getMessage());
            assertTrue(refused.getMessage().contains("key share was refused"),
                    refused.getMessage());
        }
    }

    /** Without supported_versions the header decides nothing, and TLS 1.3 was not chosen. */
    @Test
    void withoutSupportedVersionsTheServerDidNotChooseThirteen() {
        Peer peer = new Peer(id -> serverHello(id, p256Share(), false));
        assertEquals(TlsAlertException.PROTOCOL_VERSION, refused(peer).alert());
    }

    @Test
    void anExtensionThatWasNotOfferedIsRefused() {
        byte[] heartbeat = extension(15, new byte[] {1});
        Peer peer = new Peer(id -> serverHello(id,
                concat(supportedVersions(), p256Share(), heartbeat), false));
        assertEquals(TlsAlertException.UNSUPPORTED_EXTENSION, refused(peer).alert());
    }

    @Test
    void aGreaseExtensionFromTheServerIsRefused() {
        Peer peer = new Peer(id -> serverHello(id,
                concat(supportedVersions(), p256Share(), extension(0x0a0a, new byte[0])), false));
        assertEquals(TlsAlertException.UNSUPPORTED_EXTENSION, refused(peer).alert());
    }

    @Test
    void extensionsThatDoNotFillTheirLengthAreADecodeError() {
        byte[] extensions = concat(supportedVersions(), p256Share());
        Peer peer = new Peer(id -> {
            byte[] record = serverHello(id, extensions, false);
            // the extensions' length field, one too large
            int at = COMPRESSION + 1;
            int length = ((record[at] & 0xff) << 8 | (record[at + 1] & 0xff)) + 1;
            return with(with(record, at, length >>> 8), at + 1, length);
        });
        assertEquals(TlsAlertException.DECODE_ERROR, refused(peer).alert());
    }

    @Test
    void anEmptyHandshakeRecordIsRefused() throws IOException {
        Peer peer = new Peer(id -> new byte[] {22, 3, 3, 0, 0});
        peer.write(ByteBuffer.wrap(new byte[64]));
        try (RecordStream records = new RecordStream(peer)) {
            TlsProtocolException refused = assertThrows(TlsProtocolException.class, records::next);
            assertEquals(TlsAlertException.UNEXPECTED_MESSAGE, refused.alert());
        }
    }

    @Test
    void aPlaintextRecordOver2pow14IsARecordOverflow() throws IOException {
        Peer peer = new Peer(id -> new byte[] {22, 3, 3, 0x40, 1});
        peer.write(ByteBuffer.wrap(new byte[64]));
        try (RecordStream records = new RecordStream(peer)) {
            TlsProtocolException refused = assertThrows(TlsProtocolException.class, records::next);
            assertEquals(TlsAlertException.RECORD_OVERFLOW, refused.alert());
        }
    }

    @Test
    void aChangeCipherSpecAfterTheHandshakeIsRefused() throws IOException {
        byte[] ccs = {20, 3, 3, 0, 1, 1};
        Peer peer = new Peer(id -> ccs);
        peer.write(ByteBuffer.wrap(new byte[64]));     // prime the answer
        try (RecordStream records = new RecordStream(peer)) {
            records.established();
            TlsProtocolException refused = assertThrows(TlsProtocolException.class, records::next);
            assertEquals(TlsAlertException.UNEXPECTED_MESSAGE, refused.alert());
        }
    }

    @Test
    void aSecondChangeCipherSpecIsRefused() throws IOException {
        byte[] twice = {20, 3, 3, 0, 1, 1, 20, 3, 3, 0, 1, 1};
        Peer peer = new Peer(id -> twice);
        peer.write(ByteBuffer.wrap(new byte[64]));
        try (RecordStream records = new RecordStream(peer)) {
            assertThrows(TlsProtocolException.class, records::next);
        }
    }

    @Test
    void aChangeCipherSpecWithTheWrongByteIsRefused() throws IOException {
        byte[] wrong = {20, 3, 3, 0, 1, 2};
        Peer peer = new Peer(id -> wrong);
        peer.write(ByteBuffer.wrap(new byte[64]));
        try (RecordStream records = new RecordStream(peer)) {
            assertThrows(TlsProtocolException.class, records::next);
        }
    }
}
