package space.seclume.mongodb.driver.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.mongodb.ConnectionString;
import com.mongodb.MongoConfigurationException;

/** mongodb+srv:// against a stand-in DNS: what it becomes, and what it refuses. */
class SrvTest {

    private static Srv.Resolver dns(Map<String, List<String>> srv, Map<String, List<String>> txt) {
        return new Srv.Resolver() {
            @Override
            public List<String> srv(String name) {
                return srv.getOrDefault(name, List.of());
            }

            @Override
            public List<String> txt(String name) {
                return txt.getOrDefault(name, List.of());
            }
        };
    }

    private static final Srv.Resolver CLUSTER = dns(
            Map.of("_mongodb._tcp.cluster0.example.com", List.of(
                    "a.cluster0.example.com.:27017", "b.cluster0.example.com.:27018")),
            Map.of("cluster0.example.com", List.of("authSource=admin&replicaSet=rs0")));

    @Test
    void theHostsAndTheOptionsComeFromDns() {
        String expanded = Srv.expand("mongodb+srv://cluster0.example.com/shop?w=majority", CLUSTER);
        ConnectionString options = new ConnectionString(expanded);
        assertEquals(List.of("a.cluster0.example.com:27017", "b.cluster0.example.com:27018"),
                options.getHosts());
        assertEquals("rs0", options.getRequiredReplicaSetName());
        assertEquals("shop", options.getDatabase());
        assertEquals(Boolean.TRUE, options.getSslEnabled(), "TLS is on for srv");
        assertTrue(expanded.toLowerCase(java.util.Locale.ROOT).contains("authsource=admin"),
                expanded);
    }

    @Test
    void theUrlsOwnOptionWinsOverTheTxtRecord() {
        String expanded = Srv.expand("mongodb+srv://cluster0.example.com/?replicaSet=other",
                CLUSTER);
        assertEquals("other", new ConnectionString(expanded).getRequiredReplicaSetName());
    }

    /** The check that keeps DNS from sending the login elsewhere. */
    @Test
    void aTargetOutsideTheDomainIsRefused() {
        Srv.Resolver hijacked = dns(Map.of("_mongodb._tcp.cluster0.example.com",
                List.of("evil.example.org:27017")), Map.of());
        MongoConfigurationException refused = assertThrows(MongoConfigurationException.class,
                () -> Srv.expand("mongodb+srv://cluster0.example.com/", hijacked));
        assertTrue(refused.getMessage().contains("not within example.com"), refused.getMessage());
        // A name that only ends in the same letters is not within the domain either.
        Srv.Resolver lookalike = dns(Map.of("_mongodb._tcp.cluster0.example.com",
                List.of("a.badexample.com:27017")), Map.of());
        assertThrows(MongoConfigurationException.class,
                () -> Srv.expand("mongodb+srv://cluster0.example.com/", lookalike));
    }

    /**
     * A target that ends in the domain and still names another host once it
     * stands in the URL - or options, or a port that is none.
     */
    @Test
    void aTargetThatIsNotAHostNameIsRefused() {
        for (String target : List.of("evil.com:27017/?x=.example.com:27017",
                "evil.com@a.example.com:27017", "evil.com:1,a.example.com:27017",
                "a.example.com", "a.example.com:0", "a.example.com:99999",
                "a.example.com:27017?tls=false")) {
            Srv.Resolver spoilt = dns(Map.of("_mongodb._tcp.cluster0.example.com",
                    List.of(target)), Map.of());
            assertThrows(MongoConfigurationException.class,
                    () -> Srv.expand("mongodb+srv://cluster0.example.com/", spoilt), target);
        }
    }

    /** A TXT value goes into the URL as it is: nothing in it may end it and start another. */
    @Test
    void aTxtValueThatIsNotAPlainNameIsRefused() {
        for (String txt : List.of("replicaSet=rs0#x", "authSource=admin/x",
                "replicaSet=a%26tls%3Dfalse", "authSource=")) {
            Srv.Resolver spoilt = dns(Map.of("_mongodb._tcp.cluster0.example.com",
                    List.of("a.example.com:27017")), Map.of("cluster0.example.com",
                    List.of(txt)));
            assertThrows(MongoConfigurationException.class,
                    () -> Srv.expand("mongodb+srv://cluster0.example.com/", spoilt), txt);
        }
    }

    /** A host of two labels is its own domain: a target has to be below it, not it. */
    @Test
    void aShortHostNeedsTargetsBelowIt() {
        Srv.Resolver below = dns(Map.of("_mongodb._tcp.example.com",
                List.of("db1.example.com:27017")), Map.of());
        assertEquals(List.of("db1.example.com:27017"), Srv.seeds("example.com", "mongodb", below));
        Srv.Resolver itself = dns(Map.of("_mongodb._tcp.example.com",
                List.of("example.com:27017")), Map.of());
        assertThrows(MongoConfigurationException.class,
                () -> Srv.seeds("example.com", "mongodb", itself));
    }

    @Test
    void theTxtRecordMaySetOnlyThreeOptions() {
        Srv.Resolver loose = dns(Map.of("_mongodb._tcp.cluster0.example.com",
                List.of("a.cluster0.example.com:27017")),
                Map.of("cluster0.example.com", List.of("authSource=admin&tls=false")));
        MongoConfigurationException refused = assertThrows(MongoConfigurationException.class,
                () -> Srv.expand("mongodb+srv://cluster0.example.com/", loose));
        assertTrue(refused.getMessage().contains("'tls'"), refused.getMessage());
        Srv.Resolver two = dns(Map.of("_mongodb._tcp.cluster0.example.com",
                List.of("a.cluster0.example.com:27017")),
                Map.of("cluster0.example.com", List.of("authSource=a", "authSource=b")));
        assertThrows(MongoConfigurationException.class,
                () -> Srv.expand("mongodb+srv://cluster0.example.com/", two));
    }

    @Test
    void noRecordsNoPortAndOneHost() {
        assertThrows(MongoConfigurationException.class,
                () -> Srv.expand("mongodb+srv://nothing.example.com/", dns(Map.of(), Map.of())));
        assertThrows(MongoConfigurationException.class,
                () -> Srv.expand("mongodb+srv://cluster0.example.com:27017/", CLUSTER));
        assertThrows(MongoConfigurationException.class,
                () -> Srv.expand("mongodb+srv://a.example.com,b.example.com/", CLUSTER));
    }

    @Test
    void srvMaxHostsAndAServiceName() {
        Srv.Resolver many = dns(Map.of("_db._tcp.cluster0.example.com", List.of(
                "a.cluster0.example.com:1", "b.cluster0.example.com:2",
                "c.cluster0.example.com:3")), Map.of());
        String expanded = Srv.expand(
                "mongodb+srv://cluster0.example.com/?srvServiceName=db&srvMaxHosts=2", many);
        assertEquals(2, new ConnectionString(expanded).getHosts().size());
        assertTrue(!expanded.contains("srvMaxHosts") && !expanded.contains("srvServiceName"));
        assertEquals(new Srv.Name("cluster0.example.com", "db"),
                Srv.Name.of("mongodb+srv://cluster0.example.com/?srvServiceName=db"));
    }

    @Test
    void aPlainUrlIsLeftAlone() {
        assertEquals("mongodb://h:1/", Srv.expand("mongodb://h:1/", CLUSTER));
    }

    @Test
    void srvMaxHostsThatIsNoNumberIsAConfigurationError() {
        MongoConfigurationException refused = assertThrows(MongoConfigurationException.class,
                () -> Srv.expand("mongodb+srv://cluster0.example.com/?srvMaxHosts=two", CLUSTER));
        assertTrue(refused.getMessage().contains("srvMaxHosts"), refused.getMessage());
    }
}
