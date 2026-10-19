package space.seclume.mongodb.driver.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import com.mongodb.connection.ClusterConnectionMode;
import com.mongodb.connection.ClusterDescription;
import com.mongodb.connection.ServerType;

import space.seclume.mongodb.MongoUrl;

/** {@code loadBalanced=true} without a server: what is refused, and what it describes. */
class LoadBalancedOptionsTest {

    private static final String BASE = "mongodb://orders@%s/?loadBalanced=true&provider=none%s";

    /** One address, no set, no direct connection: the specification's rules for it. */
    @Test
    void aBalancerIsOneAddressAndNothingElse() {
        for (String[] refused : new String[][] {
            {"lb1.example.invalid,lb2.example.invalid", ""},
            {"lb.example.invalid", "&replicaSet=rs0"},
            {"lb.example.invalid", "&directConnection=true"}}) {
            assertThrows(IllegalArgumentException.class, () -> Topology.of(
                    MongoUrl.parse(String.format(BASE, refused[0], refused[1]))),
                    String.join("", refused));
        }
    }

    /** Nothing is monitored: no connection is opened, the balancer is the server at once. */
    @Test
    void theBalancerIsDescribedWithoutAConnection() {
        try (Topology topology = Topology.of(MongoUrl.parse(String.format(BASE,
                "lb.example.invalid:27050", "")))) {
            ClusterDescription description = topology.description();
            assertEquals(ClusterConnectionMode.LOAD_BALANCED, description.getConnectionMode());
            assertEquals(ServerType.LOAD_BALANCER,
                    description.getServerDescriptions().get(0).getType());
        }
    }
}
