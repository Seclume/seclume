package space.seclume.tls;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.RsaPss;
import space.seclume.crypto.RsaPublicKey;

/**
 * What a {@code CertificateVerify} message actually signs (RFC 8446, section
 * 4.4.3) - not the transcript hash by itself, but that hash wrapped in a
 * fixed 64-space prefix and a direction-specific context string. The prefix
 * exists to put a TLS 1.3 signature outside the range any TLS 1.2 or earlier
 * signature could ever produce; a client that skips it would accept a
 * signature meant for an entirely different protocol version.
 *
 * <p>None of this is secret - a certificate and its signature go out to
 * anyone who connects - so unlike almost everything else in this project the
 * content built here is an ordinary heap array.
 */
public final class HandshakeSignature {

    /** {@code rsa_pss_rsae_sha256} (RFC 8446, section 4.2.3) - the scheme this class can verify. */
    public static final int RSA_PSS_RSAE_SHA256 = 0x0804;

    private static final String SERVER_CONTEXT = "TLS 1.3, server CertificateVerify";
    private static final String CLIENT_CONTEXT = "TLS 1.3, client CertificateVerify";

    private HandshakeSignature() {
    }

    /**
     * The signed content for one direction: 64 spaces, the context string,
     * a zero byte, then the transcript hash.
     */
    public static byte[] content(boolean server, byte[] transcriptHash) {
        String context = server ? SERVER_CONTEXT : CLIENT_CONTEXT;
        byte[] contextBytes = context.getBytes(StandardCharsets.US_ASCII); // seclume-allow: public protocol constant
        byte[] out = new byte[64 + contextBytes.length + 1 + transcriptHash.length];
        java.util.Arrays.fill(out, 0, 64, (byte) 0x20);
        System.arraycopy(contextBytes, 0, out, 64, contextBytes.length);
        // out[64 + contextBytes.length] is already 0x00
        System.arraycopy(transcriptHash, 0, out, 64 + contextBytes.length + 1, transcriptHash.length);
        return out;
    }

    /**
     * Verifies a server's {@code CertificateVerify} against its leaf
     * certificate's RSA key.
     *
     * @return false for an unsupported {@code SignatureScheme} as well as for
     *         a signature that does not verify - a caller checking "did this
     *         succeed" needs no other case
     */
    public static boolean verifyServer(RsaPublicKey leafKey, byte[] transcriptHash,
            int signatureScheme, MemorySegment signature, long signatureOffset, int signatureLength) {
        if (signatureScheme != RSA_PSS_RSAE_SHA256) {
            return false;
        }
        byte[] content = content(true, transcriptHash);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment message = arena.allocate(content.length);
            MemorySegment.copy(content, 0, message, ValueLayout.JAVA_BYTE, 0, content.length);
            return RsaPss.verify(leafKey, HashAlgorithm.SHA_256, message, 0, content.length,
                    signature, signatureOffset, signatureLength);
        }
    }
}
