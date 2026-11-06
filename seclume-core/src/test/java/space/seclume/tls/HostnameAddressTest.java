package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.cert.X509Certificate;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * An address in the host against the iPAddress entries of a certificate:
 * IPv6 in any of its spellings, in brackets or not, and a host that only
 * looks like an address - a name with its port still on it - which is neither
 * matched nor ever handed to a resolver.
 */
class HostnameAddressTest {

    private static TestCertificates certificates;
    private static X509Certificate leaf;

    @BeforeAll
    static void aLeafWithAddresses() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        leaf = certificates.issue("addresses", "san=ip:2001:db8::7,ip:10.1.2.3,dns:db.example.com").certificate();
    }

    @AfterAll
    static void removeIt() throws Exception {
        if (certificates != null) {
            certificates.close();
        }
    }

    @Test
    void anIpv6AddressMatchesInEverySpelling() {
        for (String host : new String[] {"2001:db8::7", "2001:DB8::7", "2001:0db8:0:0:0:0:0:7",
                "[2001:db8::7]", "2001:db8:0::7"}) {
            assertTrue(HostnameMatch.matches(leaf, host), host);
        }
        assertFalse(HostnameMatch.matches(leaf, "2001:db8::8"));
        assertFalse(HostnameMatch.matches(leaf, "[2001:db8::8]"));
    }

    @Test
    void anIpv4AddressMatchesOnlyItself() {
        assertTrue(HostnameMatch.matches(leaf, "10.1.2.3"));
        assertFalse(HostnameMatch.matches(leaf, "10.1.2.30"));
        assertTrue(HostnameMatch.matches(leaf, "::ffff:10.1.2.3"),
                "an IPv4-mapped IPv6 address is that IPv4 address, as the JDK parses it");
    }

    @Test
    void aNameWithItsPortStillOnItIsNoMatchAndNoLookup() {
        long start = System.nanoTime();
        for (String host : new String[] {"db.example.com:5432", "seclume-no-such-host.invalid:1", "[db.example.com]",
                "10.1.2.3:5432"}) {
            assertFalse(HostnameMatch.matches(leaf, host), host);
        }
        // A lookup of an unresolvable name takes the resolver's timeout; four
        // refusals of what is not an address take no time at all.
        assertTrue(System.nanoTime() - start < 2_000_000_000L, "nothing was looked up");
        assertTrue(HostnameMatch.matches(leaf, "db.example.com"), "the name itself does match");
    }

    @Test
    void aLiteralIsParsedAndAnythingElseIsNot() {
        assertEquals(HostnameMatch.literal("::1"), HostnameMatch.literal("0:0:0:0:0:0:0:1"));
        assertEquals(HostnameMatch.literal("::1"), HostnameMatch.literal("[::1]"));
        assertNotNull(HostnameMatch.literal("192.0.2.1"));
        for (String text : new String[] {"db.example.com", "db.example.com:5432", "[db]", "[]", "[", "::g",
                "1.2.3.4.5", ""}) {
            assertNull(HostnameMatch.literal(text), "'" + text + "'");
        }
    }
}
