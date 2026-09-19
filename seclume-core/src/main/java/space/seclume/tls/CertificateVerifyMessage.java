package space.seclume.tls;

import java.lang.foreign.MemorySegment;

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
}
