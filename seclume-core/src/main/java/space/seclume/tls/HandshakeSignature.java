package space.seclume.tls;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;

/**
 * What a {@code CertificateVerify} message actually signs (RFC 8446, section
 * 4.4.3) - not the transcript hash by itself, but that hash wrapped in a
 * fixed 64-space prefix and a direction-specific context string. The prefix
 * exists to put a TLS 1.3 signature outside the range any TLS 1.2 or earlier
 * signature could ever produce; a client that skips it would accept a
 * signature meant for an entirely different protocol version.
 *
 * <p>The signature itself is verified through the JCA
 * ({@link Signature#getInstance "RSASSA-PSS"}), not a hand-rolled RSA-PSS -
 * per the TLS design's "what is ours and what is borrowed": this is a
 * public-key operation over public data, and there is nothing here that
 * needs to stay off the heap.
 *
 * <p>None of this is secret - a certificate and its signature go out to
 * anyone who connects - so unlike almost everything else in this project the
 * content built here is an ordinary heap array.
 */
public final class HandshakeSignature {

    /** {@code rsa_pss_rsae_sha256} (RFC 8446, section 4.2.3). */
    public static final int RSA_PSS_RSAE_SHA256 = 0x0804;
    public static final int RSA_PSS_RSAE_SHA384 = 0x0805;
    public static final int RSA_PSS_RSAE_SHA512 = 0x0806;
    public static final int ECDSA_SECP256R1_SHA256 = 0x0403;
    public static final int ECDSA_SECP384R1_SHA384 = 0x0503;
    public static final int ECDSA_SECP521R1_SHA512 = 0x0603;

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
        byte[] contextBytes = context.getBytes(java.nio.charset.StandardCharsets.US_ASCII); // seclume-allow: public protocol constant
        byte[] out = new byte[64 + contextBytes.length + 1 + transcriptHash.length];
        Arrays.fill(out, 0, 64, (byte) 0x20);
        System.arraycopy(contextBytes, 0, out, 64, contextBytes.length);
        // out[64 + contextBytes.length] is already 0x00
        System.arraycopy(transcriptHash, 0, out, 64 + contextBytes.length + 1, transcriptHash.length);
        return out;
    }

    /**
     * Verifies a server's {@code CertificateVerify} against its leaf
     * certificate's public key.
     *
     * @return false for an unsupported {@code SignatureScheme}, a key this
     *         scheme cannot use (an EC key, say), or a signature that does
     *         not verify - a caller checking "did this succeed" needs no
     *         other case
     */
    public static boolean verifyServer(PublicKey leafKey, byte[] transcriptHash,
            int signatureScheme, byte[] signature) {
        byte[] content = content(true, transcriptHash);
        try {
            Signature verifier = verifierFor(signatureScheme);
            if (verifier == null) {
                return false;
            }
            verifier.initVerify(leafKey);
            verifier.update(content);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;                     // wrong key type, malformed signature bytes, ...
        }
    }

    /**
     * A verifier for one {@code SignatureScheme}, or null for one this client
     * never offered.
     *
     * <p>The six here are exactly the six {@link ClientHello} advertises, and
     * that is the invariant worth keeping: a scheme offered but not
     * understood is a handshake that fails against a perfectly ordinary
     * server, and one understood but not offered is dead code.
     *
     * <p>The curve a scheme names is <b>not</b> checked against the key's
     * actual curve - {@code SHA256withECDSA} will verify with a P-384 key
     * just as happily. Named because it is a real gap, and a small one: the
     * signature still has to verify under the certificate the chain
     * validation already accepted.
     */
    private static Signature verifierFor(int scheme) throws GeneralSecurityException {
        return switch (scheme) {
            case RSA_PSS_RSAE_SHA256 -> pss("SHA-256", MGF1ParameterSpec.SHA256, 32);
            case RSA_PSS_RSAE_SHA384 -> pss("SHA-384", MGF1ParameterSpec.SHA384, 48);
            case RSA_PSS_RSAE_SHA512 -> pss("SHA-512", MGF1ParameterSpec.SHA512, 64);
            case ECDSA_SECP256R1_SHA256 -> Signature.getInstance("SHA256withECDSA");
            case ECDSA_SECP384R1_SHA384 -> Signature.getInstance("SHA384withECDSA");
            case ECDSA_SECP521R1_SHA512 -> Signature.getInstance("SHA512withECDSA");
            default -> null;
        };
    }

    private static Signature pss(String digest, MGF1ParameterSpec mgf1, int saltLength)
            throws GeneralSecurityException {
        Signature verifier = Signature.getInstance("RSASSA-PSS");
        // TLS 1.3 fixes the salt length to the digest length (RFC 8446, 4.2.3).
        verifier.setParameter(new PSSParameterSpec(digest, "MGF1", mgf1, saltLength, 1));
        return verifier;
    }
}
