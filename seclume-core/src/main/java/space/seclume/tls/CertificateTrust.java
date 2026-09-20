package space.seclume.tls;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Does the server's certificate chain end at something this machine trusts,
 * and was it issued for the host we connected to.
 *
 * <p><b>The chain is not validated here.</b> the TLS design settled that
 * before any of this was written: path validation is borrowed from the JCA,
 * because a certificate is public, it never travels, and a hand-written X.509
 * validator would be a security regression with nothing to show for it. So
 * this class is a thin wrapper around {@link X509TrustManager#checkServerTrusted}
 * - signatures up the chain, validity dates, basic constraints, name
 * constraints, key usage, and whatever revocation setting the operator has
 * configured for this JVM, all of it the JDK's answer rather than ours.
 *
 * <p>The default anchors are the JVM's own trust store - {@code cacerts},
 * kept current by JDK updates - which is what every other JDBC driver does
 * and what an application expects when it configures nothing. A caller with
 * an internal CA passes its own {@link KeyStore} instead.
 *
 * <p>The hostname half <em>is</em> ours, for the reason given in
 * {@link HostnameMatch}: no public API performs it without an
 * {@code SSLSocket} or {@code SSLEngine} to read a handshake session from,
 * and this client has neither.
 *
 * <p>Both halves are required and both fail closed. A chain that validates
 * for the wrong name is exactly the case this exists to refuse.
 */
public final class CertificateTrust {

    /**
     * What TLS 1.3 calls a server certificate's authentication type.
     *
     * <p>This looks like a detail and decides whether correct certificates
     * are refused. The JDK maps this string to the key usage the end-entity
     * certificate must carry: {@code "RSA"} means the old TLS_RSA key
     * exchange and demands {@code keyEncipherment}, which a TLS 1.3
     * certificate has no reason to have. TLS 1.3 authenticates by
     * <em>signature</em> and needs {@code digitalSignature}, which is what
     * the unknown-key-exchange case requires - so this is the honest value
     * as well as the working one, since TLS 1.3 has no key exchange to name.
     * {@code CertificateTrustTest} pins it down from both sides: a
     * certificate carrying only {@code digitalSignature} is accepted, and
     * one carrying only {@code keyEncipherment} is refused.
     */
    private static final String TLS13_AUTH_TYPE = "UNKNOWN";

    private final X509TrustManager trustManager;

    private CertificateTrust(X509TrustManager trustManager) {
        this.trustManager = trustManager;
    }

    /** Anchored at the JVM's own trust store - {@code cacerts} unless the operator moved it. */
    public static CertificateTrust ofDefaultTrustStore() throws GeneralSecurityException {
        return of((KeyStore) null);
    }

    /**
     * Anchored at the given store.
     *
     * @param trustStore the anchors, or {@code null} for the JVM's own
     */
    public static CertificateTrust of(KeyStore trustStore) throws GeneralSecurityException {
        TrustManagerFactory factory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trustStore);
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager x509) {
                return new CertificateTrust(x509);
            }
        }
        throw new GeneralSecurityException(
                "the trust manager factory returned no X509TrustManager, so no certificate "
                        + "could be checked against anything");
    }

    /**
     * Checks a server's chain and its name, and throws if either fails.
     *
     * @param chain    the certificates in the order the {@code Certificate}
     *                 message carried them - leaf first, then the issuers it
     *                 chose to send
     * @param hostname the name or address the connection was actually made
     *                 to, never one taken from the certificate itself
     */
    public void checkServer(List<X509Certificate> chain, String hostname)
            throws CertificateException {
        if (chain == null || chain.isEmpty()) {
            throw new CertificateException("the server sent no certificate");
        }
        trustManager.checkServerTrusted(chain.toArray(new X509Certificate[0]), TLS13_AUTH_TYPE);

        X509Certificate leaf = chain.get(0);
        if (!HostnameMatch.matches(leaf, hostname)) {
            throw new CertificateException("the certificate is valid, but not for \"" + hostname
                    + "\" - its subject alternative names do not cover that host");
        }
    }
}
