package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The Certificate and CertificateRequest bodies byte by byte, without a
 * server: where each field starts, where a length stops the walk, which
 * alert a length that lies earns, and what the client's own Certificate
 * looks like on the wire.
 *
 * <p>The handshake tests reach this code only through a socket, which is
 * slow enough that PIT timed most of its faults out on a slow runner and let
 * them survive on a fast one (pull request #334 onward: 34 to 143 timeouts a
 * run). Each test here fails, within milliseconds, on one such fault.
 *
 * <p>Every body sits at an offset of {@value #AT} in a segment that ends
 * exactly where the body does, the bytes before it 0xEE: a read that starts
 * in the wrong place reads 0xEE, and one past the end throws.
 */
class CertificateMessageTest {

    private static final int AT = 7;

    private record Entry(long certificateAt, int certificateLength, long extensionsAt, int extensionsLength) {
    }

    /** Big-endian fields appended in order. */
    private static final class Bytes {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Bytes u8(int v) {
            out.write(v);
            return this;
        }

        Bytes u16(int v) {
            return u8(v >>> 8).u8(v);
        }

        Bytes u24(int v) {
            return u8(v >>> 16).u16(v & 0xffff);
        }

        Bytes raw(byte[] b) {
            out.writeBytes(b);
            return this;
        }

        Bytes filler(int n, int seed) {
            for (int i = 0; i < n; i++) {
                out.write(seed + i);
            }
            return this;
        }

        byte[] done() {
            return out.toByteArray();
        }
    }

    /** {@code body} at offset {@link #AT}, 0xEE before it, nothing after it. */
    private static MemorySegment placed(Arena arena, byte[] body) {
        MemorySegment s = arena.allocate(AT + body.length);
        s.fill((byte) 0xEE);
        MemorySegment.copy(body, 0, s, ValueLayout.JAVA_BYTE, AT, body.length);
        return s;
    }

    private static List<Entry> walk(MemorySegment s, int length) {
        List<Entry> seen = new ArrayList<>();
        CertificateMessage.certificates(s, AT, length,
                (certAt, certLength, extAt, extLength) -> seen.add(new Entry(certAt, certLength, extAt, extLength)));
        return seen;
    }

    private static List<Entry> walk(byte[] body) {
        try (Arena arena = Arena.ofConfined()) {
            return walk(placed(arena, body), body.length);
        }
    }

    private static TlsProtocolException serverCertificateRefused(byte[] body) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = placed(arena, body);
            return assertThrows(TlsProtocolException.class,
                    () -> CertificateMessage.checkServerCertificate(s, AT, body.length));
        }
    }

    private static void serverCertificateAccepted(byte[] body) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = placed(arena, body);
            assertDoesNotThrow(() -> CertificateMessage.checkServerCertificate(s, AT, body.length));
        }
    }

    private static TlsProtocolException requestRefused(byte[] body) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = placed(arena, body);
            return assertThrows(TlsProtocolException.class,
                    () -> CertificateMessage.checkCertificateRequest(s, AT, body.length));
        }
    }

    /** Context, list length, then the entries as given. */
    private static byte[] certificate(byte[] context, byte[] entries) {
        return new Bytes().u8(context.length).raw(context).u24(entries.length).raw(entries).done();
    }

    private static byte[] entry(int certificateLength, int seed, byte[] extensions) {
        return new Bytes().u24(certificateLength).filler(certificateLength, seed)
                .u16(extensions.length).raw(extensions).done();
    }

    private static byte[] concat(byte[]... parts) {
        Bytes b = new Bytes();
        for (byte[] p : parts) {
            b.raw(p);
        }
        return b.done();
    }

    // --- certificates: the walk ---

    @Test
    void everyEntryIsFoundWhereItIsAfterARequestContext() {
        byte[] extensions = new Bytes().u16(5).u16(0).done();
        byte[] body = certificate(new byte[] {1, 2},
                concat(entry(3, 0x10, new byte[0]), entry(2, 0x20, extensions)));

        // context: length byte and two bytes; list length: three; then
        // entry one: length 3, certificate 3, extensions length 2.
        long first = AT + 1 + 2 + 3 + 3;
        long second = first + 3 + 2 + 3;
        assertEquals(List.of(
                new Entry(first, 3, first + 3 + 2, 0),
                new Entry(second, 2, second + 2 + 2, 4)), walk(body));
    }

    @Test
    void aBodyThatEndsAfterItsContextHasNoEntriesAndIsNotReadPast() {
        byte[] body = new Bytes().u8(2).u8(9).u8(9).done();
        assertEquals(List.of(), walk(body), "no room for a list length: nothing to walk");
    }

    @Test
    void bytesAfterTheListAreNotAnEntry() {
        byte[] list = entry(2, 0x30, new byte[0]);
        byte[] trailing = entry(1, 0x40, new byte[0]);
        byte[] body = concat(certificate(new byte[0], list), trailing);

        List<Entry> seen = walk(body);
        assertEquals(1, seen.size(), "the list says where it ends: " + seen);
        assertEquals(AT + 1 + 3 + 3, seen.get(0).certificateAt());
    }

    @Test
    void aListLongerThanTheBodyIsWalkedAsFarAsItGoes() {
        byte[] one = entry(4, 0x50, new byte[0]);
        byte[] body = new Bytes().u8(0).u24(one.length + 100).raw(one).done();

        assertEquals(List.of(new Entry(AT + 1 + 3 + 3, 4, AT + 1 + 3 + 3 + 4 + 2, 0)), walk(body));
    }

    @Test
    void anEntryWithoutRoomForItsExtensionsLengthStopsTheWalkInsideTheBody() {
        // Certificate length, the certificate, and one byte of the two that
        // would say how long its extensions are. The body ends there.
        byte[] cut = new Bytes().u24(3).filler(3, 1).u8(0).done();
        byte[] body = certificate(new byte[0], cut);

        assertEquals(List.of(), walk(body));
    }

    @Test
    void extensionsLongerThanWhatIsLeftStopTheWalk() {
        byte[] lying = new Bytes().u24(2).filler(2, 1).u16(5).u16(0).done();
        byte[] body = certificate(new byte[0], lying);

        assertEquals(List.of(), walk(body), "five bytes of extensions announced, two there");
    }

    @Test
    void aCertificateOfMoreThan64KiBKeepsItsLength() {
        int large = 70_000;
        byte[] body = certificate(new byte[0], entry(large, 0, new byte[0]));

        assertEquals(List.of(new Entry(AT + 1 + 3 + 3, large, AT + 1 + 3 + 3 + large + 2, 0)), walk(body));
        serverCertificateAccepted(body);
    }

    // --- checkServerCertificate: the shape a server's Certificate must have ---

    @Test
    void aWellFormedChainOfTwoPasses() {
        serverCertificateAccepted(certificate(new byte[0],
                concat(entry(5, 1, new byte[0]), entry(7, 2, new byte[0]))));
    }

    @Test
    void fewerThanFourBytesIsADecodeErrorThatSaysHowMany() {
        TlsProtocolException e = serverCertificateRefused(new byte[] {0, 0, 0});
        assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        assertTrue(e.getMessage().contains("of 3 bytes"), e.getMessage());
    }

    @Test
    void aRequestContextFromTheServerIsAnIllegalParameter() {
        TlsProtocolException e = serverCertificateRefused(
                certificate(new byte[] {1}, entry(3, 1, new byte[0])));
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, e.alert());
    }

    @Test
    void aListLengthThatIsNotTheRestOfTheMessageSaysBoth() {
        byte[] entries = entry(1, 1, new byte[0]);
        byte[] body = concat(new Bytes().u8(0).u24(entries.length - 1).done(), entries);

        TlsProtocolException e = serverCertificateRefused(body);
        assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        assertTrue(e.getMessage().contains("says 5 bytes and the message has 6"), e.getMessage());
    }

    @Test
    void fourBytesLeftInTheListAreATruncatedEntry() {
        byte[] body = certificate(new byte[0], concat(entry(2, 1, new byte[0]), new byte[] {0, 0, 1, 9}));

        TlsProtocolException e = serverCertificateRefused(body);
        assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        assertTrue(e.getMessage().contains("truncated certificate entry"), e.getMessage());
    }

    @Test
    void fiveBytesLeftAreAnEntryThatCannotHoldACertificate() {
        // Five bytes: a length, and room for the extensions length, but none
        // for a certificate of length one - checked as an entry, not as a
        // truncated one.
        byte[] body = certificate(new byte[0], new byte[] {0, 0, 1, 0, 0});

        TlsProtocolException e = serverCertificateRefused(body);
        assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        assertTrue(e.getMessage().contains("a certificate longer than its list"), e.getMessage());
    }

    @Test
    void anEmptyCertificateEntryIsADecodeError() {
        TlsProtocolException e = serverCertificateRefused(certificate(new byte[0], entry(0, 0, new byte[0])));
        assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        assertTrue(e.getMessage().contains("a certificate longer than its list"), e.getMessage());
    }

    @Test
    void aCertificateOneByteLongerThanItsListIsADecodeError() {
        // The entry says six bytes of certificate; five follow, then the two
        // bytes of an empty extensions block.
        byte[] lying = new Bytes().u24(6).filler(5, 1).u16(0).done();

        TlsProtocolException e = serverCertificateRefused(certificate(new byte[0], lying));
        assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        assertTrue(e.getMessage().contains("a certificate longer than its list"), e.getMessage());
    }

    @Test
    void extensionsLongerThanTheListAreADecodeError() {
        byte[] lying = new Bytes().u24(2).filler(2, 1).u16(4).u16(5).done();

        TlsProtocolException e = serverCertificateRefused(certificate(new byte[0], lying));
        assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        assertTrue(e.getMessage().contains("certificate extensions longer than the list"), e.getMessage());
    }

    @Test
    void anExtensionOnACertificateIsOneThisClientDidNotAskFor() {
        byte[] statusRequest = new Bytes().u16(5).u16(0).done();
        byte[] body = certificate(new byte[0], concat(entry(3, 1, new byte[0]), entry(3, 2, statusRequest)));

        TlsProtocolException e = serverCertificateRefused(body);
        assertEquals(TlsAlertException.UNSUPPORTED_EXTENSION, e.alert());
    }

    // --- checkCertificateRequest ---

    private static byte[] request(byte[] context, byte[] extensions) {
        return new Bytes().u8(context.length).raw(context).u16(extensions.length).raw(extensions).done();
    }

    private static final byte[] SIGNATURE_ALGORITHMS = new Bytes().u16(13).u16(4).u16(2).u16(0x0403).done();

    @Test
    void aRequestWithSignatureAlgorithmsPasses() {
        byte[] body = request(new byte[0], SIGNATURE_ALGORITHMS);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = placed(arena, body);
            assertDoesNotThrow(() -> CertificateMessage.checkCertificateRequest(s, AT, body.length));
        }
    }

    @Test
    void aContextLongerThanTheRequestIsADecodeError() {
        TlsProtocolException e = requestRefused(new byte[] {3, 1});
        assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        assertTrue(e.getMessage().contains("context of 3 bytes"), e.getMessage());
    }

    @Test
    void aContextThatFillsTheRequestIsStillAContext() {
        // One byte of context, exactly what the message has room for: not a
        // length that lies, but a context, which the handshake must not have.
        TlsProtocolException e = requestRefused(new byte[] {1, 1});
        assertEquals(TlsAlertException.ILLEGAL_PARAMETER, e.alert());
    }

    @Test
    void aRequestWithoutSignatureAlgorithmsIsMissingAnExtension() {
        TlsProtocolException e = requestRefused(request(new byte[0], new Bytes().u16(0x2c).u16(0).done()));
        assertEquals(TlsAlertException.MISSING_EXTENSION, e.alert());
    }

    // --- the client's own Certificate ---

    @Test
    void theClientsCertificateIsWrittenByteForByte() {
        byte[] context = {9, 8};
        List<byte[]> chain = List.of(new byte[] {1, 2, 3}, new byte[] {4});
        byte[] expected = new Bytes()
                .u8(Handshake.CERTIFICATE).u24(1 + 2 + 3 + (3 + 3 + 2) + (3 + 1 + 2))
                .u8(2).u8(9).u8(8)
                .u24((3 + 3 + 2) + (3 + 1 + 2))
                .u24(3).u8(1).u8(2).u8(3).u16(0)
                .u24(1).u8(4).u16(0)
                .done();

        int size = CertificateMessage.sizeFor(context, chain);
        assertEquals(expected.length, size, "sizeFor is what write needs, no more and no less");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(size);
            out.fill((byte) 0xFF);
            assertEquals(expected.length, CertificateMessage.write(out, context, chain));
            assertArrayEquals(expected, out.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @Test
    void aClientCertificateOfMoreThan64KiBReadsBackAsWritten() {
        byte[] large = new byte[70_000];
        Arrays.fill(large, (byte) 0x5A);
        List<byte[]> chain = List.of(large);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(CertificateMessage.sizeFor(new byte[0], chain));
            out.fill((byte) 0xFF);
            int written = CertificateMessage.write(out, new byte[0], chain);

            assertEquals(Handshake.CERTIFICATE, out.get(ValueLayout.JAVA_BYTE, 0));
            int bodyLength = written - Handshake.HEADER;
            int header = (out.get(ValueLayout.JAVA_BYTE, 1) & 0xff) << 16
                    | (out.get(ValueLayout.JAVA_BYTE, 2) & 0xff) << 8 | out.get(ValueLayout.JAVA_BYTE, 3) & 0xff;
            assertEquals(bodyLength, header, "the header's length");
            assertEquals(1 + 3 + 3 + large.length + 2, bodyLength);
            List<Entry> seen = new ArrayList<>();
            CertificateMessage.certificates(out, Handshake.HEADER, bodyLength,
                    (certAt, certLength, extAt, extLength) -> seen.add(new Entry(certAt, certLength, extAt, extLength)));
            assertEquals(List.of(new Entry(Handshake.HEADER + 1 + 3 + 3, large.length,
                    Handshake.HEADER + 1 + 3 + 3 + large.length + 2, 0)), seen);
        }
    }

    @Test
    void theRequestContextIsCopiedFromWhereItIs() {
        byte[] body = request(new byte[] {7, 6, 5}, new byte[0]);
        try (Arena arena = Arena.ofConfined()) {
            assertArrayEquals(new byte[] {7, 6, 5}, CertificateMessage.requestContext(placed(arena, body), AT));
        }
    }
}
