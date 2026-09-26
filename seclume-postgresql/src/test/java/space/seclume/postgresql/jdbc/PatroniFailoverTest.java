package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import space.seclume.tck.TestHosts;

/**
 * {@code patroni=}: the URL names only a server that is gone, and the cluster
 * - a stand-in answering {@code /cluster} as Patroni documents it - says where
 * its leader is now. The connection gets there; without the option it does not.
 */
class PatroniFailoverTest {

    @Test
    void theClusterSaysWhereTheLeaderIs() throws Exception {
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no " + TestHosts.postgresPasswordFile());
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + host);
        }
        String cluster = "{\"members\": ["
                + "{\"name\": \"old\", \"role\": \"replica\", \"state\": \"stopped\", "
                + "\"host\": \"127.0.0.1\", \"port\": 1},"
                + "{\"name\": \"new\", \"role\": \"leader\", \"state\": \"running\", "
                + "\"host\": \"" + host + "\", \"port\": " + port + "}]}";
        String base = "jdbc:seclume:postgresql://127.0.0.1:1/seclume_test?user=seclume_test"
                + "&tls=off&connectTimeout=1000&targetServerType=primary&provider=file&path="
                + password.toString().replace('\\', '/');
        try (ServerSocket patroni = serve(cluster)) {
            try (Connection c = DriverManager.getConnection(base + "&patroni=http://127.0.0.1:"
                    + patroni.getLocalPort());
                 Statement s = c.createStatement();
                 ResultSet rows = s.executeQuery("select pg_is_in_recovery()")) {
                rows.next();
                assertEquals("f", rows.getString(1), "not the leader");
            }
        }
        // The control: the URL alone knows only the server that is gone.
        assertThrows(SQLException.class, () -> DriverManager.getConnection(base).close());
    }

    /** One resource, answered to every request. */
    private static ServerSocket serve(String body) throws IOException {
        ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            while (!server.isClosed()) {
                try (Socket client = server.accept()) {
                    client.getInputStream().read(new byte[4096]);
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
