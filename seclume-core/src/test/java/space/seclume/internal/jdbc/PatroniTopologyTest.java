package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/** A {@code /cluster} answer in the shape Patroni documents, read and ordered. */
class PatroniTopologyTest {

    static final String CLUSTER = """
            {
              "members": [
                {"name": "pg1", "role": "replica", "state": "streaming", "api_url": "http://10.0.0.1:8008/patroni",
                 "host": "10.0.0.1", "port": 5432, "timeline": 3, "lag": 0},
                {"name": "pg2", "role": "leader", "state": "running", "api_url": "http://10.0.0.2:8008/patroni",
                 "host": "10.0.0.2", "port": 5433, "timeline": 3},
                {"name": "pg3", "role": "replica", "state": "stopped", "host": "10.0.0.3", "port": 5432},
                {"name": "pg4", "role": "sync_standby", "state": "streaming", "host": "10.0.0.4", "port": 5432,
                 "tags": {"nofailover": false}, "lag": "unknown"}
              ],
              "scope": "orders"
            }
            """;

    @Test
    void theMembersAreReadAsPatroniListsThem() {
        List<PatroniTopology.Member> members = PatroniTopology.parse(CLUSTER);
        assertEquals(4, members.size());
        assertEquals(new PatroniTopology.Member("10.0.0.2", 5433, "leader", "running"), members.get(1));
    }

    @Test
    void theLeaderFirstForAPrimaryAndTheReplicasFirstForASecondary() throws IOException {
        AtomicInteger asked = new AtomicInteger();
        try (ServerSocket patroni = serve(CLUSTER, asked)) {
            // A dead endpoint first: the next one is asked.
            PatroniTopology cluster = PatroniTopology.of("http://127.0.0.1:1,http://127.0.0.1:"
                    + patroni.getLocalPort());
            assertEquals("[10.0.0.2:5433, 10.0.0.1:5432, 10.0.0.4:5432]",
                    cluster.hosts(TargetServer.PRIMARY).toString());
            assertEquals("[10.0.0.1:5432, 10.0.0.4:5432, 10.0.0.2:5433]",
                    cluster.hosts(TargetServer.SECONDARY).toString());
            assertEquals(1, asked.get(), "the answer was not kept for the second call");
        }
    }

    /**
     * The driver's URL decides which servers Patroni may name: a member the
     * answer lists that is not one of the URL's hosts - an answer over plain
     * HTTP, or from an endpoint taken over - is not connected to.
     */
    @Test
    void aUrlsPatroniNamesOnlyTheUrlsOwnHosts() throws IOException {
        try (ServerSocket patroni = serve(CLUSTER, new AtomicInteger())) {
            String prefix = "jdbc:seclume:postgresql:";
            space.seclume.internal.JdbcUrl.Parsed parsed = space.seclume.internal.JdbcUrl.parse(
                    prefix + "//10.0.0.1:5432,10.0.0.2:5433/app?patroni=http://127.0.0.1:"
                            + patroni.getLocalPort(), null, prefix, 5432);
            assertEquals("[10.0.0.2:5433, 10.0.0.1:5432]",
                    parsed.hosts().topology().hosts(TargetServer.PRIMARY).toString(),
                    "10.0.0.4 is no host of the URL");
        }
    }

    /**
     * Patroni names members by address; a URL that names its servers by host
     * name matched none of them. patroniHosts= admits addresses in the
     * ranges it names - 10.0.0.4 when 10.0.0.0/30 is not enough, and only then.
     */
    @Test
    void patroniHostsAdmitsMembersByTheirAddress() throws IOException {
        try (ServerSocket patroni = serve(CLUSTER, new AtomicInteger())) {
            String prefix = "jdbc:seclume:postgresql:";
            String url = prefix + "//db1.example.com,db2.example.com/app?patroni=http://127.0.0.1:"
                    + patroni.getLocalPort();
            assertEquals("[]", space.seclume.internal.JdbcUrl.parse(url, null, prefix, 5432)
                    .hosts().topology().hosts(TargetServer.PRIMARY).toString(),
                    "no member is a host of the URL");
            assertEquals("[10.0.0.2:5433, 10.0.0.1:5432]", space.seclume.internal.JdbcUrl.parse(
                    url + "&patroniHosts=10.0.0.0/30", null, prefix, 5432)
                    .hosts().topology().hosts(TargetServer.PRIMARY).toString(),
                    "10.0.0.4 is outside 10.0.0.0/30");
            assertEquals("[10.0.0.2:5433, 10.0.0.1:5432, 10.0.0.4:5432]",
                    space.seclume.internal.JdbcUrl.parse(url + "&patroniHosts=10.0.0.0/29",
                            null, prefix, 5432).hosts().topology().hosts(TargetServer.PRIMARY)
                            .toString());
        }
    }

    /** Ranges are address/bits; anything else is refused when the URL is read. */
    @Test
    void aRangeThatIsNoneIsRefused() {
        for (String bad : new String[] {"10.0.0.0", "10.0.0.0/33", "db.example.com/24",
                "10.0.0.0/x", "::1/129"}) {
            org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                    () -> PatroniTopology.of("https://p:8008", List.of("db"), bad), bad);
        }
        assertTrue(PatroniTopology.Range.of("fd00::/8").contains(
                PatroniTopology.Range.address("fd12::5")));
        org.junit.jupiter.api.Assertions.assertFalse(PatroniTopology.Range.of("fd00::/8")
                .contains(PatroniTopology.Range.address("10.0.0.1")));
    }

    /**
     * An endpoint without a scheme was asked over plain http, where anybody on
     * the way writes the answer that picks the server. It is https now; http
     * only when the URL says so, and no other scheme at all.
     */
    @Test
    void anEndpointWithoutASchemeIsAskedOverHttps() {
        assertEquals("https", PatroniTopology.of("db1:8008").endpoints().get(0).getScheme());
        assertEquals("http", PatroniTopology.of("http://db1:8008").endpoints().get(0).getScheme());
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> PatroniTopology.of("file:///etc/passwd"));
    }

    /**
     * An answer nested without end - over plain HTTP anybody's - was a
     * StackOverflowError out of connect, which the pool does not catch.
     */
    @Test
    void nestingDeeperThan64IsRefused() {
        String deep = "[".repeat(65) + "]".repeat(65);
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> PatroniTopology.parse("{\"members\": " + deep + "}"));
        String deeper = "[".repeat(100_000);
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> PatroniTopology.parse("{\"members\": " + deeper + "}"));
        PatroniTopology.parse("{\"x\": " + "[".repeat(60) + "]".repeat(60)
                + ", \"members\": []}");                                  // within: read
    }

    @Test
    void noAnswerMeansNoMembers() {
        assertTrue(PatroniTopology.of("http://127.0.0.1:1").hosts(TargetServer.PRIMARY).isEmpty());
        assertNull(PatroniTopology.of(null));
        assertNull(PatroniTopology.of(" "));
    }

    /** A Patroni REST endpoint of one resource: every request gets {@code body}. */
    static ServerSocket serve(String body, AtomicInteger asked) throws IOException {
        ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            while (!server.isClosed()) {
                try (Socket client = server.accept()) {
                    client.getInputStream().read(new byte[4096]);
                    asked.incrementAndGet();
                    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                    OutputStream out = client.getOutputStream();
                    out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            + "Content-Length: " + bytes.length + "\r\nConnection: close\r\n\r\n")
                            .getBytes(StandardCharsets.US_ASCII));
                    out.write(bytes);
                } catch (IOException closed) {
                    return;
                }
            }
        });
        return server;
    }
}
