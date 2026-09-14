package space.seclume.internal;

import java.lang.foreign.MemorySegment;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Locale;

import space.seclume.crypto.HashAlgorithm;

/**
 * {@code tls-server-end-point} — the channel binding of RFC 5929.
 *
 * <p>What it is for: SCRAM proves that both sides know the password, and
 * nothing more. Somebody sitting in the middle can hold two TLS connections,
 * pass the SCRAM messages through unchanged and end up with a logged-in
 * session on both sides. Channel binding closes that by mixing a fingerprint
 * of <b>the certificate of the connection actually being used</b> into the
 * proof: the value differs on the two connections, so the relayed proof does
 * not fit.
 *
 * <p>That is why it is worth having even with {@code tls=require} and no
 * certificate check: the client need not know <em>who</em> the server is to
 * notice that the answer came from a different connection than the one it is
 * on.
 *
 * <p>The binding data is the hash of the certificate in DER form. The hash is
 * <b>chosen by the certificate's signature algorithm</b>, not fixed: SHA-256
 * for a certificate signed with SHA-256, SHA-384 for SHA-384, and so on, with
 * MD5 and SHA-1 lifted to SHA-256 because the specification says so.
 */
public final class ChannelBinding {

    /** The name that goes into the GS2 header. */
    public static final String TYPE = "tls-server-end-point";

    private ChannelBinding() {
    }

    /**
     * Writes the fingerprint of the server certificate into {@code out}.
     *
     * @return how many bytes were written - between 32 and 64
     * @throws IllegalArgumentException if the certificate's signature
     *         algorithm is one whose hash we cannot name. That is deliberately
     *         an error and not a fallback: a binding computed with the wrong
     *         hash is not detectably wrong, it just fails the login with a
     *         message about the password, and silently dropping the binding
     *         instead would give up exactly the protection it exists for.
     */
    public static int endPoint(X509Certificate certificate, MemorySegment out) {
        HashAlgorithm algorithm = hashFor(certificate.getSigAlgName());
        byte[] der; // seclume-allow: the server's certificate is public information, not a secret
        try {
            der = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException(
                    "the server's certificate cannot be encoded: " + e.getMessage(), e);
        }
        MemorySegment source = MemorySegment.ofArray(der);
        algorithm.hash(source, 0, der.length, out, 0);
        return algorithm.digestLength();
    }

    /**
     * The hash belonging to a signature algorithm, as RFC 5929 section 4.1
     * prescribes.
     *
     * <p>Decided on the name rather than the OID because that is what the
     * platform hands out. Names look like {@code SHA256withRSA},
     * {@code SHA384withECDSA}, {@code SHA1withDSA}.
     */
    public static HashAlgorithm hashFor(String signatureAlgorithm) {
        String name = signatureAlgorithm == null ? ""
                : signatureAlgorithm.toUpperCase(Locale.ROOT).replace("-", "");
        // "MD5 and SHA-1 are upgraded to SHA-256" - not for strength here but
        // because the specification fixes it, and both sides have to agree.
        if (name.startsWith("MD5") || name.startsWith("SHA1")) {
            return HashAlgorithm.SHA_256;
        }
        if (name.startsWith("SHA256")) {
            return HashAlgorithm.SHA_256;
        }
        if (name.startsWith("SHA384")) {
            return HashAlgorithm.SHA_384;
        }
        if (name.startsWith("SHA512")) {
            return HashAlgorithm.SHA_512;
        }
        throw new IllegalArgumentException(
                "the server's certificate is signed with \"" + signatureAlgorithm
                + "\", and seclume cannot tell which hash belongs to that. Channel binding "
                + "needs the right one - the login would fail with a misleading message "
                + "otherwise. RSASSA-PSS certificates land here, because the hash sits in the "
                + "parameters rather than in the name.");
    }

    /** The longest fingerprint that can come out, so callers can size a buffer. */
    public static final int MAX_LENGTH = 64;
}
