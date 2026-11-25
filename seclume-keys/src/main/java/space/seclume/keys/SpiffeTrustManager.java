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
    /** The workload's own trust domain: without peer-ids, the only one trusted. */
    private final Supplier<String> own;

    /**
     * @param bundles the CAs for a trust domain - empty for one without a bundle
     * @param issuers every CA, for {@link #getAcceptedIssuers}
     * @param peers   the SPIFFE IDs a peer may have; empty for any workload of
     *                this workload's own trust domain - a federated one's only
     *                when named here
     * @param own     this workload's trust domain, from its current SVID
     */
    SpiffeTrustManager(Function<String, List<X509Certificate>> bundles,
            Supplier<List<X509Certificate>> issuers, Set<String> peers, Supplier<String> own) {
        this.own = own;
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
        leafOnly(chain[0]);
        if (peers.isEmpty() && !domain.equals(own.get())) {
            // A federated domain's workloads are trusted for what they are named
            // for, not for anything: without peer-ids only this workload's own.
            throw new CertificateException("the peer is of the federated trust domain " + domain
                    + "; name it in peer-ids to accept it");
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

    /**
     * An X509-SVID's leaf as the specification has it: not a CA, and where
     * it says what its key is for, for signatures and not for signing
     * certificates or CRLs. A CA certificate with a SPIFFE URI in it passed
     * as a peer's leaf - this trust manager is not the JDK's, which would
     * have checked the key usage.
     */
    static void leafOnly(X509Certificate leaf) throws CertificateException {
        if (leaf.getBasicConstraints() != -1) {
            throw new CertificateException("the peer's SVID is a CA certificate, not a leaf");
        }
        boolean[] usage = leaf.getKeyUsage();
        if (usage != null && (!usage[0] || (usage.length > 5 && usage[5])
                || (usage.length > 6 && usage[6]))) {
            throw new CertificateException("the peer's SVID is not for digital signatures "
                    + "only - it may sign certificates or CRLs, or not sign at all");
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
