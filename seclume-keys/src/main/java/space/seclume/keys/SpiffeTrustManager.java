package space.seclume.keys;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Trusts a peer the way SPIFFE does: its leaf names exactly one SPIFFE ID
 * ({@code spiffe://...} as its only URI SAN), and its chain leads to a CA of
 * the bundle of <b>that ID's trust domain</b> - the workload's own, or one it
 * federates with, as the Workload API gave them last, so a rotated bundle
 * counts at once. A peer of a domain without a bundle is refused, and so is
 * one whose ID claims a domain its CA does not speak for. If a set of IDs is
 * given, the peer's has to be one of them. Host names play no part: an SVID
 * has none to check.
 */
final class SpiffeTrustManager extends X509ExtendedTrustManager {

    private final Function<String, List<X509Certificate>> bundles;
    private final Supplier<List<X509Certificate>> issuers;
    private final Set<String> peers;

    /**
     * @param bundles the CAs for a trust domain - empty for one without a bundle
     * @param issuers every CA, for {@link #getAcceptedIssuers}
     * @param peers   the SPIFFE IDs a peer may have; empty for any of the trust
     *                domains that have a bundle
     */
    SpiffeTrustManager(Function<String, List<X509Certificate>> bundles,
            Supplier<List<X509Certificate>> issuers, Set<String> peers) {
        this.bundles = bundles;
        this.issuers = issuers;
        this.peers = Set.copyOf(peers);
    }

    void check(X509Certificate[] chain) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("the peer showed no certificate");
        }
        // The ID first - read, not yet believed - because its trust domain says
        // whose CAs the chain has to lead to.
        String id = spiffeId(chain[0]);
        String domain;
        try {
            domain = space.seclume.secret.SpiffeWorkloadApi.trustDomain(id);
        } catch (IllegalArgumentException e) {
            throw new CertificateException("the peer's SPIFFE ID is malformed: "
                    + e.getMessage(), e);
        }
        List<X509Certificate> anchors = bundles.apply(domain);
        if (anchors.isEmpty()) {
            throw new CertificateException("the peer is of the trust domain " + domain
                    + ", for which the Workload API gave no bundle - not this workload's, "
                    + "not one it federates with");
        }
        try {
            Set<TrustAnchor> trust = new HashSet<>();
            for (X509Certificate ca : anchors) {
                trust.add(new TrustAnchor(ca, null));
            }
            PKIXParameters parameters = new PKIXParameters(trust);
            parameters.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509")
                    .generateCertPath(Arrays.asList(chain)), parameters);
        } catch (GeneralSecurityException e) {
            throw new CertificateException("the peer's certificate is not from the CAs of "
                    + domain + ": " + e.getMessage(), e);
        }
        if (!peers.isEmpty() && !peers.contains(id)) {
            throw new CertificateException("the peer is " + id + ", which is not one of "
                    + peers);
        }
    }

    /** The one SPIFFE ID of an SVID - and refused if there is none or more than one URI. */
    static String spiffeId(X509Certificate leaf) throws CertificateException {
        String id = null;
        try {
            Collection<List<?>> names = leaf.getSubjectAlternativeNames();
            if (names != null) {
                for (List<?> name : names) {
                    if (Integer.valueOf(6).equals(name.get(0))) {           // a URI
                        if (id != null) {
                            throw new CertificateException("an SVID has one URI, this "
                                    + "certificate has more");
                        }
                        id = String.valueOf(name.get(1));
                    }
                }
            }
        } catch (CertificateParsingException e) {
            throw new CertificateException("the peer's names cannot be read", e);
        }
        if (id == null || !id.startsWith("spiffe://")) {
            throw new CertificateException("the peer's certificate is no SVID: no spiffe:// URI");
        }
        return id;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        check(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        check(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        check(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        check(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        check(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        check(chain);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return issuers.get().toArray(X509Certificate[]::new);
    }
}
