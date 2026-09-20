package space.seclume.tls;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * Whether a certificate was issued for the host we actually connected to
 * (RFC 6125, and RFC 2818 for the IP case).
 *
 * <p><b>Why this is ours when path validation is borrowed.</b>
 * the TLS design puts certificate validation in the JCA's hands, and
 * {@link CertificateTrust} keeps it there. The JDK does have this check too -
 * {@code sun.security.util.HostnameChecker} - but every public way in goes
 * through an {@code SSLSocket} or {@code SSLEngine}:
 * {@link javax.net.ssl.X509ExtendedTrustManager} only performs it when it can
 * read a <em>handshake session</em> off one, and a client with its own record
 * layer has neither. There is no supported API that takes a certificate and a
 * hostname. So this is written here rather than reached for, and it is worth
 * knowing that it is the one part of certificate checking this project owns.
 *
 * <p>The rules, each of which has been a real vulnerability somewhere:
 *
 * <ul>
 *   <li><b>Subject Alternative Names only.</b> A name in the Common Name is
 *       ignored outright - the CA/Browser Forum has forbidden relying on it
 *       for years, and honouring it is how certificates for one name get
 *       accepted for another;
 *   <li><b>a wildcard replaces exactly one whole label, and only the
 *       leftmost.</b> {@code *.example.com} matches {@code db.example.com},
 *       and neither {@code a.b.example.com} nor bare {@code example.com}.
 *       Partial labels ({@code db*.example.com}) are not honoured even though
 *       RFC 6125 tolerates them: no public CA issues them any more, and a
 *       prefix match is a wide door for a name nobody intended;
 *   <li><b>a wildcard needs three labels below it.</b> {@code *.com} is
 *       refused. Without that rule one certificate covers a whole top-level
 *       domain;
 *   <li><b>a literal IP address matches only an iPAddress entry</b>, never a
 *       DNS name and never a wildcard - {@code *.1.2.3} is not a thing, and
 *       treating an address as a name is how it would become one.
 * </ul>
 *
 * <p>Nothing here resolves anything. A hostname is compared as text and an
 * address as an address; no name is ever looked up, because a check that
 * consults DNS can be answered by whoever controls DNS.
 */
public final class HostnameMatch {

    private static final int DNS_NAME = 2;
    private static final int IP_ADDRESS = 7;

    private HostnameMatch() {
    }

    /**
     * Whether {@code host} - the name or address the connection was actually
     * made to - is covered by the certificate.
     */
    public static boolean matches(X509Certificate certificate, String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String wanted = normalise(host);
        Collection<List<?>> names;
        try {
            names = certificate.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            return false;                 // an unreadable extension is not a match
        }
        if (names == null) {
            return false;                 // no SAN at all: nothing to match, and no CN fallback
        }

        boolean literalAddress = isLiteralAddress(wanted);
        for (List<?> entry : names) {
            if (entry == null || entry.size() < 2) {
                continue;
            }
            if (!(entry.get(0) instanceof Integer type) || !(entry.get(1) instanceof String value)) {
                continue;                 // an othername arrives as a byte[]; not something we match
            }
            if (literalAddress) {
                if (type == IP_ADDRESS && addressesEqual(wanted, value)) {
                    return true;
                }
            } else if (type == DNS_NAME && matchesPattern(normalise(value), wanted)) {
                return true;
            }
        }
        return false;
    }

    /**
     * One {@code dNSName} pattern against one hostname, both already
     * lower-cased and stripped of a trailing dot.
     */
    static boolean matchesPattern(String pattern, String host) {
        if (pattern.isEmpty() || host.isEmpty()) {
            return false;
        }
        if (!pattern.startsWith("*.")) {
            return pattern.equals(host);  // an asterisk anywhere else is not honoured
        }
        String suffix = pattern.substring(1);                 // ".example.com"
        if (countLabels(pattern) < 3) {
            return false;                                     // "*.com" covers too much
        }
        if (!host.endsWith(suffix)) {
            return false;                                     // also rules out the bare domain
        }
        String label = host.substring(0, host.length() - suffix.length());
        return !label.isEmpty() && label.indexOf('.') < 0;     // exactly one label, and a real one
    }

    /** Lower case, and without the trailing dot of a fully qualified name. */
    private static String normalise(String name) {
        String out = name.trim().toLowerCase(Locale.ROOT);
        if (out.endsWith(".")) {
            out = out.substring(0, out.length() - 1);
        }
        return out;
    }

    private static int countLabels(String name) {
        int labels = 1;
        for (int i = 0; i < name.length(); i++) {
            if (name.charAt(i) == '.') {
                labels++;
            }
        }
        return labels;
    }

    /**
     * Whether the text is an IP address rather than a name. Deliberately
     * decided by shape alone - a name is never handed to a resolver to find
     * out what it is.
     */
    private static boolean isLiteralAddress(String host) {
        if (host.indexOf(':') >= 0) {
            return true;                  // no hostname contains a colon
        }
        int digits = 0;
        int dots = 0;
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c == '.') {
                dots++;
            } else if (c >= '0' && c <= '9') {
                digits++;
            } else {
                return false;
            }
        }
        return dots == 3 && digits > 0;
    }

    /**
     * Two addresses, compared as addresses. IPv4 is exact text; IPv6 goes
     * through {@link InetAddress} so that {@code ::1} and {@code 0:0:0:0:0:0:0:1}
     * are recognised as one address. Only strings already known to be
     * literals reach this, so nothing is resolved.
     */
    private static boolean addressesEqual(String host, String fromCertificate) {
        String other = fromCertificate.trim();
        if (host.equalsIgnoreCase(other)) {
            return true;
        }
        if (host.indexOf(':') < 0 && other.indexOf(':') < 0) {
            return false;                 // two IPv4 literals that differ as text differ
        }
        try {
            return InetAddress.getByName(host).equals(InetAddress.getByName(other));
        } catch (UnknownHostException e) {
            return false;
        }
    }
}
