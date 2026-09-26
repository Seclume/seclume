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
