package space.seclume.crypto;

import java.lang.foreign.MemorySegment;

/**
 * Just enough X.509 (RFC 5280) to get from a DER certificate to the RSA
 * public key it carries - nothing about validity, extensions, issuer or
 * chain building. That belongs to a caller that has decided what "trusted"
 * means for this connection; this is only the mechanical part every such
 * decision needs first.
 *
 * <p>{@code TBSCertificate} is walked field by field rather than by name,
 * because DER gives no other way to skip past {@code version} (present only
 * from v2 certificates on, and {@code EXPLICIT}-tagged so it looks like
 * nothing else in the sequence), {@code serialNumber}, {@code signature},
 * {@code issuer} and {@code validity} to reach {@code subjectPublicKeyInfo}.
 *
 * <p>A certificate is not a secret - it goes out on the wire to anyone who
 * connects - so unlike almost everything else in this project this is
 * ordinary DER parsing with no requirement to stay off-heap in the caller.
 */
public final class X509 {

    private X509() {
    }

    /**
     * The RSA public key from a DER-encoded {@code Certificate} (RFC 5280,
     * section 4.1) - the exact bytes TLS's {@code CertificateEntry.cert_data}
     * carries.
     *
     * @throws IllegalArgumentException if the structure cannot be walked, or
     *                                   its key is not RSA (only
     *                                   {@code subjectPublicKeyInfo} is read;
     *                                   the algorithm identifier inside it is
     *                                   what actually decides that, and
     *                                   {@link RsaPublicKey#fromSubjectPublicKeyInfo}
     *                                   does not check it either - a non-RSA
     *                                   key here produces nonsense numbers,
     *                                   not a clean rejection. Not yet a
     *                                   defect: this driver offers no other
     *                                   TLS signature scheme to fall back to.
     */
    public static RsaPublicKey rsaPublicKey(MemorySegment certificateDer, long offset, int length) {
        Der.Reader certificate = new Der.Reader(certificateDer, offset, length).readSequence();
        Der.Reader tbs = certificate.readSequence();
        if (tbs.peekTag() == 0xA0) {          // [0] EXPLICIT Version, absent in a v1 certificate
            tbs.skipElement();
        }
        tbs.skipElement();                    // serialNumber
        tbs.skipElement();                    // signature (AlgorithmIdentifier)
        tbs.skipElement();                    // issuer
        tbs.skipElement();                    // validity
        tbs.skipElement();                    // subject
        Der.Range spki = tbs.readElement();   // subjectPublicKeyInfo, header and all
        return RsaPublicKey.fromSubjectPublicKeyInfo(certificateDer.asSlice(spki.offset(), spki.length()));
    }
}
