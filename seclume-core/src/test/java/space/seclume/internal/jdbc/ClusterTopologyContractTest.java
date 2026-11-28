package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ServerSocket;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The rule every ClusterTopology keeps: discovery may reorder the servers
 * the URL names, never add one. An answer - Patroni's REST API, an Aurora
 * cluster's own table - that names a host of its choosing does not send the
 * login there; the cluster's other mechanisms (MongoDB's SeedDomains, Redis's
 * mayReceive, Kafka's broker check) are held to the same rule in their own
 * modules.
 */
class ClusterTopologyContractTest {

    /** Patroni's answer with a member the URL never named. */
    private static final String WITH_A_STRANGER = PatroniTopologyTest.CLUSTER.replace(
            "\"host\": \"10.0.0.2\"", "\"host\": \"attacker.example\"");

    @AfterEach
    void forget() {
        AuroraTopology.forgetAll();
    }

    @Test
    void patroniNamesOnlyTheUrlsHosts() throws Exception {
        try (ServerSocket patroni = PatroniTopologyTest.serve(WITH_A_STRANGER, new AtomicInteger())) {
            String endpoint = "http://127.0.0.1:" + patroni.getLocalPort();
            List<String> urlHosts = List.of("10.0.0.1", "10.0.0.4");
            for (TargetServer wanted : TargetServer.values()) {
                for (HostList.Host host : PatroniTopology.of(endpoint, urlHosts).hosts(wanted)) {
                    assertTrue(urlHosts.contains(host.host()),
                            wanted + ": discovery added " + host);
                }
            }
            // Without the URL's hosts there is nothing to hold the answer to: nothing is taken.
            assertEquals(List.of(), PatroniTopology.of(endpoint).hosts(TargetServer.ANY));
        }
    }

    @Test
    void auroraBuildsEveryHostInTheClustersOwnDomain() {
        List<HostList.Host> url = List.of(new HostList.Host(
                "orders.cluster-abc123.eu-central-1.rds.amazonaws.com", 5432));
        AuroraTopology aurora = AuroraTopology.of("true", null, url);
        aurora.learn("attacker.example=true,evil.attacker.example.=false,instance-1=false,"
                + "instance-2=true,x/../y=false");
        for (TargetServer wanted : TargetServer.values()) {
            for (HostList.Host host : aurora.hosts(wanted)) {
                boolean theUrls = url.contains(host);
                boolean anInstance = host.host().endsWith(".abc123.eu-central-1.rds.amazonaws.com")
                        && host.host().indexOf('.') == host.host().indexOf(".abc123");
                assertTrue(theUrls || anInstance,
                        wanted + ": a host outside the cluster's domain or with labels of the "
                        + "answer's choosing: " + host);
            }
        }
        assertEquals(1, aurora.hosts(TargetServer.PRIMARY).stream()
                .filter(h -> h.host().startsWith("instance-2.")).count(), "the real writer");
    }
}
