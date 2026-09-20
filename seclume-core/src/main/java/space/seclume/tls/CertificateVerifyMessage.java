package space.seclume.tls;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * The TLS 1.3 {@code CertificateVerify} message body (RFC 8446, section
 * 4.4.3): a two-byte {@code SignatureScheme}, then a length-prefixed
 * signature. Nothing more - what the signature actually covers is
 * {@link HandshakeSignature#content}, built from the transcript, not from
 * anything in this message.
 */
public final class CertificateVerifyMessage {

    private CertificateVerifyMessage() {
    }

    public static int signatureScheme(MemorySegment body, long offset) {
        return Handshake.u16(body, offset);
    }

    public static int signatureLength(MemorySegment body, long offset) {
        return Handshake.u16(body, offset + 2);
    }

    public static long signatureOffset(long offset) {
        return offset + 4;
    }

    /**
     * Writes the client's own {@code CertificateVerify}, header and all.
     *
     * <p>Nothing in it is secret. The signature proves the client holds the
     * key that belongs to the certificate it just sent, and it is meant to be
     * read by the server - so it travels as an ordinary array, while the key
     * that produced it never left the provider. See {@link ClientIdentity}.
     *
     * @return how many bytes of {@code out} were written
     */
    public static int write(MemorySegment out, int scheme, byte[] signature) {
        int body = 4 + signature.length;
        out.set(ValueLayout.JAVA_BYTE, 0, (byte) Handshake.CERTIFICATE_VERIFY);
        out.set(ValueLayout.JAVA_BYTE, 1, (byte) (body >>> 16));
        out.set(ValueLayout.JAVA_BYTE, 2, (byte) (body >>> 8));
        out.set(ValueLayout.JAVA_BYTE, 3, (byte) body);
        long at = Handshake.HEADER;
        out.set(ValueLayout.JAVA_BYTE, at, (byte) (scheme >>> 8));
        out.set(ValueLayout.JAVA_BYTE, at + 1, (byte) scheme);
        out.set(ValueLayout.JAVA_BYTE, at + 2, (byte) (signature.length >>> 8));
        out.set(ValueLayout.JAVA_BYTE, at + 3, (byte) signature.length);
        MemorySegment.copy(signature, 0, out, ValueLayout.JAVA_BYTE, at + 4, signature.length);
        return Handshake.HEADER + body;
    }
}
