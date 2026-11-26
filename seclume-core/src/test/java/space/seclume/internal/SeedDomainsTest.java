package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The one rule for hosts a cluster announces - MongoDB's members, Kafka's
 * brokers: discovery may reorder the configured hosts, never extend them
 * beyond their domains and what is explicitly allowed.
 */
class SeedDomainsTest {

    @Test
    void theSeedsTheirDomainAndAllowedSuffixes() {
        List<String> seeds = SeedDomains.hostsOf(List.of("db1.corp.example:27017",
                "SASL_SSL://b1.kafka.corp.example:9093", "[2001:db8::1]:9093", "10.0.0.5"));
        assertEquals(List.of("db1.corp.example", "b1.kafka.corp.example", "2001:db8::1",
                "10.0.0.5"), seeds);
        assertTrue(SeedDomains.admits("db1.corp.example", seeds, List.of()));
        assertTrue(SeedDomains.admits("DB2.corp.example", seeds, List.of()), "the seed's domain");
        assertTrue(SeedDomains.admits("b9.kafka.corp.example", seeds, List.of()));
        assertTrue(SeedDomains.admits("2001:db8::1", seeds, List.of()));
        assertFalse(SeedDomains.admits("2001:db8::2", seeds, List.of()), "an address admits itself");
        assertFalse(SeedDomains.admits("10.0.0.6", seeds, List.of()));
        assertFalse(SeedDomains.admits("evil.example", seeds, List.of()));
        assertFalse(SeedDomains.admits("corp.example.evil.example", seeds, List.of()));
        assertTrue(SeedDomains.admits("x.partner.example", seeds,
                SeedDomains.suffixes("*.partner.example")));
        assertFalse(SeedDomains.admits("x.notpartner.example", seeds,
                SeedDomains.suffixes("partner.example")));
    }

    @Test
    void aSingleLabelSeedAdmitsOnlyItself() {
        // "localhost" has no parent domain to share.
        List<String> seeds = List.of("localhost");
        assertTrue(SeedDomains.admits("localhost", seeds, List.of()));
        assertFalse(SeedDomains.admits("evil.localhost", seeds, List.of()));
    }
}
