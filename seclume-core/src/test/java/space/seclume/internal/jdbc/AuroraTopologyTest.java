package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** How instances are named, and in which order they are tried after the cluster spoke. */
class AuroraTopologyTest {

    private static final HostList.Host ENDPOINT =
            new HostList.Host("app.cluster-abc123.eu-central-1.rds.amazonaws.com", 5432);

    @BeforeEach
    void forget() {
        AuroraTopology.forgetAll();
    }

    @Test
    void offUnlessAsked() {
        assertNull(AuroraTopology.of(null, null, List.of(ENDPOINT)));
        assertNull(AuroraTopology.of("false", null, List.of(ENDPOINT)));
    }

    @Test
    void nothingKnownKeepsTheUrlsHosts() {
        AuroraTopology aurora = AuroraTopology.of("true", null, List.of(ENDPOINT));
        assertTrue(aurora.hosts(TargetServer.PRIMARY).isEmpty());
        assertTrue(aurora.due());
    }

    @Test
    void theWriterFirstForPrimaryTheReadersFirstForSecondaryTheEndpointLast() {
        AuroraTopology aurora = AuroraTopology.of("true", null, List.of(ENDPOINT));
        aurora.learn("app-2=false,app-1=true,app-3=f");
        String suffix = ".abc123.eu-central-1.rds.amazonaws.com";
        assertEquals(List.of(host("app-1" + suffix), host("app-2" + suffix),
                host("app-3" + suffix), ENDPOINT), aurora.hosts(TargetServer.PRIMARY));
        assertEquals(List.of(host("app-2" + suffix), host("app-3" + suffix),
                host("app-1" + suffix), ENDPOINT), aurora.hosts(TargetServer.SECONDARY));
        assertFalse(aurora.due(), "asked again within the second");
    }

    @Test
    void aReaderEndpointNamesTheSameInstances() {
        AuroraTopology writer = AuroraTopology.of("true", null, List.of(ENDPOINT));
        AuroraTopology reader = AuroraTopology.of("true", null, List.of(new HostList.Host(
                "app.cluster-ro-abc123.eu-central-1.rds.amazonaws.com", 5432)));
        writer.learn("app-1=1,app-2=0");
        assertEquals(host("app-1.abc123.eu-central-1.rds.amazonaws.com"),
                reader.hosts(TargetServer.PRIMARY).get(0), "one cluster, one memory");
    }

    @Test
    void anExplicitPatternWithAPort() {
        AuroraTopology aurora = AuroraTopology.of("true", "?.internal.example:6432",
                List.of(new HostList.Host("10.0.0.1", 5432)));
        aurora.learn("db-a=t");
        assertEquals(new HostList.Host("db-a.internal.example", 6432),
                aurora.hosts(TargetServer.ANY).get(0));
    }

    @Test
    void anUnreadableAnswerKeepsTheLastGoodOne() {
        AuroraTopology aurora = AuroraTopology.of("true", null, List.of(ENDPOINT));
        aurora.learn("app-1=true");
        aurora.learn("");
        aurora.learn("../etc=true,a b=false,=true");
        assertEquals(2, aurora.hosts(TargetServer.PRIMARY).size());
    }

    @Test
    void aRefusalIsNotAskedAgainForAMinute() {
        AuroraTopology aurora = AuroraTopology.of("true", null, List.of(ENDPOINT));
        aurora.refused();
        assertFalse(AuroraTopology.of("true", null, List.of(ENDPOINT)).due(),
                "a new connection to the same cluster asked again at once");
    }

    @Test
    void withoutAClusterEndpointThePatternMustBeNamed() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> AuroraTopology.of("true", null, List.of(new HostList.Host("db", 5432))));
        assertTrue(refused.getMessage().contains("auroraInstanceHost"));
        assertThrows(IllegalArgumentException.class,
                () -> AuroraTopology.of("true", "db.example", List.of(ENDPOINT)));
    }

    private static HostList.Host host(String name) {
        return new HostList.Host(name, 5432);
    }
}
