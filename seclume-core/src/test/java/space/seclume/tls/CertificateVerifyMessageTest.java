package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import org.junit.jupiter.api.Test;

/**
 * The client's own CertificateVerify, written into a buffer of 0xFF so that
 * a byte not written shows, and read back by the same accessors the
 * handshake reads the server's with. Signatures of 300 and 65,535 bytes put
 * something into every byte of every length field.
 *
 * <p>The handshake tests write this message only for a server that asks for
 * a client certificate, over a socket; PIT timed those faults out on a slow
 * runner and let them survive on a fast one.
 */
class CertificateVerifyMessageTest {

    private static final int SCHEME = 0x0804;      // rsa_pss_rsae_sha256

    private static byte[] signature(int length) {
        byte[] s = new byte[length];
        for (int i = 0; i < length; i++) {
            s[i] = (byte) (i * 7 + 1);
        }
        return s;
    }

    private static MemorySegment written(Arena arena, byte[] signature) {
        MemorySegment out = arena.allocate(Handshake.HEADER + 4 + signature.length);
        out.fill((byte) 0xFF);
        assertEquals(out.byteSize(), CertificateVerifyMessage.write(out, SCHEME, signature),
                "write says how much it wrote");
        return out;
    }

    @Test
    void aSignatureOf300BytesIsWrittenByteForByte() {
        byte[] sig = signature(300);
        try (Arena arena = Arena.ofConfined()) {
            byte[] wire = written(arena, sig).toArray(ValueLayout.JAVA_BYTE);
            int body = 4 + sig.length;
            byte[] head = {
                (byte) Handshake.CERTIFICATE_VERIFY, 0, (byte) (body >>> 8), (byte) body,
                0x08, 0x04, (byte) (sig.length >>> 8), (byte) sig.length,
            };
            for (int i = 0; i < head.length; i++) {
                assertEquals(head[i], wire[i], "byte " + i);
            }
            byte[] rest = new byte[sig.length];
            System.arraycopy(wire, head.length, rest, 0, rest.length);
            assertArrayEquals(sig, rest);
        }
    }

    @Test
    void theLargestSignatureReadsBackThroughTheAccessors() {
        byte[] sig = signature(0xFFFF);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = written(arena, sig);
            int body = 4 + sig.length;           // more than three bytes' worth of 64 KiB
            assertEquals(Handshake.CERTIFICATE_VERIFY, out.get(ValueLayout.JAVA_BYTE, 0));
            assertEquals(body >>> 16, out.get(ValueLayout.JAVA_BYTE, 1) & 0xff);
            assertEquals((body >>> 8) & 0xff, out.get(ValueLayout.JAVA_BYTE, 2) & 0xff);
            assertEquals(body & 0xff, out.get(ValueLayout.JAVA_BYTE, 3) & 0xff);

            long at = Handshake.HEADER;
            assertEquals(SCHEME, CertificateVerifyMessage.signatureScheme(out, at));
            assertEquals(sig.length, CertificateVerifyMessage.signatureLength(out, at));
            assertDoesNotThrow(() -> CertificateVerifyMessage.checkShape(out, at, body));
            long signatureAt = CertificateVerifyMessage.signatureOffset(at);
            assertArrayEquals(sig, out.asSlice(signatureAt, sig.length).toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @Test
    void aMessageTooShortForItsOwnHeaderIsADecodeError() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment body = arena.allocate(4);
            body.set(ValueLayout.JAVA_BYTE, 3, (byte) 0);
            TlsProtocolException e = assertThrows(TlsProtocolException.class,
                    () -> CertificateVerifyMessage.checkShape(body, 0, 3));
            assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        }
    }

    @Test
    void anEmptySignatureIsADecodeError() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment body = written(arena, new byte[0]);
            TlsProtocolException e = assertThrows(TlsProtocolException.class,
                    () -> CertificateVerifyMessage.checkShape(body, Handshake.HEADER, 4));
            assertEquals(TlsAlertException.DECODE_ERROR, e.alert());
        }
    }
}
