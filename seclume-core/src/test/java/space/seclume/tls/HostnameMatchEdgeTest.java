package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * The edges of the hostname check: the shape that makes a host an address,
 * the labels a wildcard may cover, and subject alternative names a
 * certificate parser can hand over that are no name at all.
 *
 * <p>The certificate here is a stand-in that has nothing but its subject
 * alternative names - exactly what {@link HostnameMatch#matches} reads - so
 * each test sets the one list it is about, including entries no CA would
 * issue and keytool cannot make. {@code HostnameAddressTest} covers the same
 * method with real certificates; PIT still found the address-shape check
 * and the label count unchecked (run 43416680859, {@code HostnameMatch}: 10
 * survivors).
 */
class HostnameMatchEdgeTest {

    private static final int DNS = 2;
    private static final int IP = 7;

    /** A certificate that is only its subject alternative names. */
    private static final class Names extends X509Certificate {
        private static final long serialVersionUID = 1L;
        private final transient Collection<List<?>> names;
        private final boolean unreadable;

        Names(Collection<List<?>> names, boolean unreadable) {
            this.names = names;
            this.unreadable = unreadable;
        }

        @Override
        public Collection<List<?>> getSubjectAlternativeNames() throws CertificateParsingException {
            if (unreadable) {
                throw new CertificateParsingException("a broken extension");
            }
            return names;
        }

        // Nothing else of a certificate is read by the hostname check.
        @Override public void checkValidity() { throw new UnsupportedOperationException(); }
        @Override public void checkValidity(Date date) { throw new UnsupportedOperationException(); }
        @Override public int getVersion() { throw new UnsupportedOperationException(); }
        @Override public BigInteger getSerialNumber() { throw new UnsupportedOperationException(); }
        @Deprecated @Override public Principal getIssuerDN() { throw new UnsupportedOperationException(); }
        @Deprecated @Override public Principal getSubjectDN() { throw new UnsupportedOperationException(); }
        @Override public Date getNotBefore() { throw new UnsupportedOperationException(); }
        @Override public Date getNotAfter() { throw new UnsupportedOperationException(); }
        @Override public byte[] getTBSCertificate() { throw new UnsupportedOperationException(); }
        @Override public byte[] getSignature() { throw new UnsupportedOperationException(); }
        @Override public String getSigAlgName() { throw new UnsupportedOperationException(); }
        @Override public String getSigAlgOID() { throw new UnsupportedOperationException(); }
        @Override public byte[] getSigAlgParams() { throw new UnsupportedOperationException(); }
        @Override public boolean[] getIssuerUniqueID() { throw new UnsupportedOperationException(); }
        @Override public boolean[] getSubjectUniqueID() { throw new UnsupportedOperationException(); }
        @Override public boolean[] getKeyUsage() { throw new UnsupportedOperationException(); }
        @Override public int getBasicConstraints() { throw new UnsupportedOperationException(); }
        @Override public byte[] getEncoded() { throw new UnsupportedOperationException(); }
        @Override public void verify(PublicKey key) { throw new UnsupportedOperationException(); }
        @Override public void verify(PublicKey key, String sigProvider) { throw new UnsupportedOperationException(); }
        @Override public String toString() { return "Names" + names; }
        @Override public PublicKey getPublicKey() { throw new UnsupportedOperationException(); }
        @Override public boolean hasUnsupportedCriticalExtension() { throw new UnsupportedOperationException(); }
        @Override public Set<String> getCriticalExtensionOIDs() { throw new UnsupportedOperationException(); }
        @Override public Set<String> getNonCriticalExtensionOIDs() { throw new UnsupportedOperationException(); }
        @Override public byte[] getExtensionValue(String oid) { throw new UnsupportedOperationException(); }
    }

    private static X509Certificate certificate(Object... typeAndValue) {
        List<List<?>> names = new ArrayList<>();
        for (int i = 0; i < typeAndValue.length; i += 2) {
            names.add(Arrays.asList(typeAndValue[i], typeAndValue[i + 1]));
        }
        return new Names(names, false);
    }

    /** An address matches only an iPAddress entry: a DNS entry spelled like it is a name. */
    @Test
    void anAddressIsNeverMatchedByADnsEntrySpelledLikeIt() {
        for (String address : List.of("10.0.0.1", "192.0.2.9", "9.9.9.9", "0.0.0.0")) {
            assertFalse(HostnameMatch.matches(certificate(DNS, address), address),
                    address + " taken for a name");
            assertTrue(HostnameMatch.matches(certificate(IP, address), address),
                    address + " not taken for an address");
        }
    }

    /** Anything that is not digits and three dots is a name - and a name never matches an address. */
    @Test
    void whatIsNotFourNumbersIsANameAndMatchesNoAddress() {
        X509Certificate both = certificate(IP, "10.0.0.1", DNS, "10.0.0.1x", DNS, "a.b.c.d");
        assertTrue(HostnameMatch.matches(both, "10.0.0.1x"), "a letter makes it a name");
        assertTrue(HostnameMatch.matches(both, "a.b.c.d"), "three dots alone do not make an address");
        assertFalse(HostnameMatch.matches(certificate(IP, "10.0.1"), "10.0.1"),
                "two dots: a name, and an iPAddress entry is never compared with a name");
        assertFalse(HostnameMatch.matches(certificate(IP, "10.0.0.0.1"), "10.0.0.0.1"));
    }

    /** An IPv4-mapped IPv6 address is that IPv4 address, on either side. */
    @Test
    void anIpv4MappedAddressIsComparedAsTheAddressItIs() {
        assertTrue(HostnameMatch.matches(certificate(IP, "10.0.0.1"), "::ffff:10.0.0.1"));
        assertTrue(HostnameMatch.matches(certificate(IP, "::ffff:10.0.0.1"), "10.0.0.1"));
        assertFalse(HostnameMatch.matches(certificate(IP, "10.0.0.1"), "::ffff:10.0.0.2"));
        assertFalse(HostnameMatch.matches(certificate(IP, "::1"), "0.0.0.1"));
    }

    @Test
    void twoIpv4AddressesThatDifferAsTextDiffer() {
        assertFalse(HostnameMatch.matches(certificate(IP, "10.0.0.1"), "10.0.0.2"));
        assertFalse(HostnameMatch.matches(certificate(IP, "10.0.0.01"), "10.0.0.1"),
                "a leading zero is not read as the same address");
        assertTrue(HostnameMatch.matches(certificate(IP, " 10.0.0.1 "), "10.0.0.1"),
                "the certificate's entry is trimmed");
    }

    /** A wildcard covers one real label: an empty one in front is not a label. */
    @Test
    void aWildcardDoesNotCoverAHostWithAnEmptyFirstLabel() {
        assertFalse(HostnameMatch.matchesPattern("*.example.com", ".db.example.com"));
        assertFalse(HostnameMatch.matchesPattern("*.example.com", "..example.com"));
        assertTrue(HostnameMatch.matchesPattern("*.example.com", "db.example.com"), "control");
    }

    /**
     * A wildcard needs at least two labels beside it, also under a top-level
     * name the Public Suffix List does not list - {@code *.corp} would
     * otherwise cover every host of a private top-level name. (The list's
     * default rule refuses these too; the label count is the second wall.)
     */
    @Test
    void aWildcardNextToOneLabelCoversNothingEvenUnderAnUnknownSuffix() {
        for (String tld : List.of("corp", "lan", "home", "seclume-test")) {
            assertFalse(HostnameMatch.matchesPattern("*." + tld, "db." + tld), "*." + tld);
            assertTrue(HostnameMatch.matchesPattern("*.example." + tld, "db.example." + tld),
                    "control: *.example." + tld);
        }
    }

    /** What a parser can hand over that is no name: skipped, and the rest still read. */
    @Test
    void entriesThatAreNoNameAreSkippedAndTheRestStillCount() {
        List<List<?>> names = new ArrayList<>();
        names.add(null);
        names.add(List.of());
        names.add(List.of(DNS));
        names.add(Arrays.asList("2", "db.example.com"));                   // a type that is no number
        names.add(Arrays.asList(0, new byte[] {1, 2, 3}));                 // an otherName, as bytes
        names.add(Arrays.asList(DNS, null));
        names.add(Arrays.asList(1, "db.example.com"));                    // an rfc822Name
        X509Certificate odd = new Names(names, false);
        assertFalse(HostnameMatch.matches(odd, "db.example.com"), "none of these is a dNSName entry");
        names.add(Arrays.asList(DNS, "db.example.com"));
        assertTrue(HostnameMatch.matches(odd, "db.example.com"), "a real one after them still matches");
    }

    @Test
    void noNamesAnUnreadableExtensionOrNoHostMatchNothing() {
        assertFalse(HostnameMatch.matches(new Names(null, false), "db.example.com"),
                "no SAN at all - and no fallback to the Common Name");
        assertFalse(HostnameMatch.matches(new Names(List.of(), true), "db.example.com"));
        X509Certificate good = certificate(DNS, "db.example.com");
        assertFalse(HostnameMatch.matches(good, null));
        assertFalse(HostnameMatch.matches(good, ""));
        assertFalse(HostnameMatch.matches(good, "  "));
        assertTrue(HostnameMatch.matches(good, "DB.Example.COM."), "case and a trailing dot do not matter");
    }

    /** Brackets around an address are taken off only when there is something between them. */
    @Test
    void bracketsAreTakenOffOnlyAroundSomething() {
        assertNull(HostnameMatch.literal("[]"));
        assertNull(HostnameMatch.literal("[::1"));
        assertNull(HostnameMatch.literal("::1]"));
        assertNull(HostnameMatch.literal("1::1]"), "a closing bracket alone takes nothing off");
        assertNull(HostnameMatch.literal("[1::1"));
        assertTrue(HostnameMatch.matches(certificate(IP, "::1"), "[::1]"));
        assertTrue(HostnameMatch.matches(certificate(IP, "[::1]"), "::1"));
    }
}
