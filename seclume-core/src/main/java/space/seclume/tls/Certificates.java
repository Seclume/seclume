package space.seclume.tls;

import java.io.ByteArrayInputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * DER bytes off a {@code Certificate} message, turned into a
 * {@link X509Certificate} - through the JDK's own parser and nothing this
 * project wrote, per {@code docs/tls.md}'s "what is ours and what is
 * borrowed": a certificate is not a secret, it goes out on the wire to
 * anyone who connects, and a hand-rolled X.509 reader would be a place for a
 * parsing bug to become a security bug for no offsetting benefit.
 */
public final class Certificates {

    private Certificates() {
    }

    /** Parses one {@code CertificateEntry}'s {@code cert_data}. */
    public static X509Certificate parse(MemorySegment der, long offset, int length)
            throws CertificateException {
        byte[] bytes = der.asSlice(offset, length).toArray(ValueLayout.JAVA_BYTE);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(bytes));
    }
}
