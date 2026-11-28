package space.seclume.mongodb.driver.internal;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Every host in a hello's member lists got a connection, and with it the
 * SCRAM proof, the AWS signature or the OIDC token: one compromised member or
 * an rs.reconfig could bring in a host of its choosing. Discovery may name
 * the seeds' hosts, hosts in a seed's parent domain, and configured suffixes.
 */
class AnnouncedMemberTest {

    @Test
    void theSeedsAndTheirDomainMayJoin() {
        List<String> seeds = List.of("rs1.db.example.org", "127.0.0.1");
        assertTrue(Topology.mayJoin("rs1.db.example.org", seeds, List.of()));
        assertTrue(Topology.mayJoin("RS3.db.example.org", seeds, List.of()));
        assertTrue(Topology.mayJoin("127.0.0.1", seeds, List.of()));
        assertTrue(Topology.mayJoin("mongo.partner.example", seeds, List.of("partner.example")));
    }

    @Test
    void anythingElseIsRefused() {
        List<String> seeds = List.of("rs1.db.example.org", "10.0.0.5");
        assertFalse(Topology.mayJoin("attacker.example", seeds, List.of()));
        assertFalse(Topology.mayJoin("rs1.db.example.org.attacker.example", seeds, List.of()));
        assertFalse(Topology.mayJoin("other.example.org", seeds, List.of()),
                "a seed's domain is its parent's, not the whole of example.org");
        assertFalse(Topology.mayJoin("10.0.0.6", seeds, List.of()), "an IP seed admits itself only");
        assertFalse(Topology.mayJoin("x.example", List.of("db.example"), List.of()),
                "a two-label seed admits no siblings");
    }
}
