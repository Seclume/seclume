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
import java.util.function.Supplier;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Trusts a peer the way SPIFFE does: its chain leads to a CA of the trust
 * bundle the Workload API gave - the latest one, so a rotated bundle counts at
 * once - and its leaf names exactly one SPIFFE ID ({@code spiffe://...} as its
 * only URI SAN), which, if a set of IDs is given, has to be one of them. Host
 * names play no part: an SVID has none to check.
 */
final class SpiffeTrustManager extends X509ExtendedTrustManager {

    private final Supplier<List<X509Certificate>> bundle;
    private final Set<String> peers;

    /** @param peers the SPIFFE IDs a peer may have; empty for any of the trust domain */
    SpiffeTrustManager(Supplier<List<X509Certificate>> bundle, Set<String> peers) {
        this.bundle = bundle;
        this.peers = Set.copyOf(peers);
    }

    void check(X509Certificate[] chain) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("the peer showed no certificate");
        }
        List<X509Certificate> anchors = bundle.get();
        if (anchors.isEmpty()) {
            throw new CertificateException("the Workload API gave no trust bundle");
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
            throw new CertificateException("the peer's certificate is not from the trust "
                    + "domain's CAs: " + e.getMessage(), e);
        }
        String id = spiffeId(chain[0]);
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
        return bundle.get().toArray(X509Certificate[]::new);
    }
}
