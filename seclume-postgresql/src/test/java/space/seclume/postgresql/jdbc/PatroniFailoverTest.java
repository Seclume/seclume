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
 * {@code patroni=}: the cluster - a stand-in answering {@code /cluster} as
 * Patroni documents it - says which of the URL's servers leads now, and the
 * connection gets there. It may reorder the URL's servers, not add one: an
 * answer naming a server the URL does not, over plain HTTP or from an endpoint
 * taken over, would send the login anywhere.
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
        String query = "/seclume_test?user=seclume_test"
                + "&tls=off&connectTimeout=1000&targetServerType=primary&provider=file&path="
                + password.toString().replace('\\', '/');
        // The server that is gone has a name no real one has (RFC 2606): with
        // 127.0.0.1 here, a database on 127.0.0.1 - as in CI - was the same
        // host to Patroni's check, and the leader was taken as the URL's own.
        String both = "jdbc:seclume:postgresql://gone.invalid:1," + host + ":" + port + query;
        String goneOnly = "jdbc:seclume:postgresql://gone.invalid:1" + query;
        try (ServerSocket patroni = serve(cluster)) {
            String asked = "&patroni=http://127.0.0.1:" + patroni.getLocalPort();
            // The leader is not on the URL: the answer cannot add it.
            assertThrows(SQLException.class,
                    () -> DriverManager.getConnection(goneOnly + asked).close());
            try (Connection c = DriverManager.getConnection(both + asked);
                 Statement s = c.createStatement();
                 ResultSet rows = s.executeQuery("select pg_is_in_recovery()")) {
                rows.next();
                assertEquals("f", rows.getString(1), "not the leader");
            }
        }
        // The control: the URL alone knows only the server that is gone.
        assertThrows(SQLException.class, () -> DriverManager.getConnection(goneOnly).close());
    }

    /**
     * Patroni names, as the leader, a server the URL does not - one that
     * listens, and would ask for the password in cleartext. The driver, with
     * the URL's own server gone, fails; that server never sees a connection,
     * let alone a password. Runs without a database.
     */
    @Test
    void aLeaderTheUrlDoesNotNameNeverSeesAConnection() throws Exception {
        java.util.concurrent.atomic.AtomicInteger accepted =
                new java.util.concurrent.atomic.AtomicInteger();
        Path secret = Files.createTempFile("patroni-test", ".pw");
        Files.writeString(secret, "decoy-password-not-real");
        String provider = "&provider=file&path=" + secret.toString().replace('\\', '/');
        try (ServerSocket stranger = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            Thread.ofVirtual().start(() -> {
                while (!stranger.isClosed()) {
                    try (Socket client = stranger.accept()) {
                        accepted.incrementAndGet();
                        // AuthenticationCleartextPassword - what it would ask for
                        client.getOutputStream().write(new byte[] {'R', 0, 0, 0, 8, 0, 0, 0, 3});
                        client.getInputStream().read(new byte[4096]);
                    } catch (IOException closed) {
                        return;
                    }
                }
            });
            final String cluster = "{\"members\": [{\"name\": \"rogue\", \"role\": \"leader\", "
                    + "\"state\": \"running\", \"host\": \"127.0.0.1\", \"port\": "
                    + stranger.getLocalPort() + "}]}";
            try (ServerSocket patroni = serve(cluster)) {
                String url = "jdbc:seclume:postgresql://localhost:1/app?user=app&tls=off"
                        + "&connectTimeout=1000&targetServerType=primary" + provider
                        + "&patroni=http://127.0.0.1:" + patroni.getLocalPort();
                java.util.Properties properties = new java.util.Properties();
                assertThrows(SQLException.class,
                        () -> DriverManager.getConnection(url, properties).close());
            }
            Thread.sleep(200);
            assertEquals(0, accepted.get(), "the server only Patroni named got a connection");
            // The control: with its host on the URL the same member is dialled -
            // the stand-in is reachable, and the test would see a connection.
            try (ServerSocket patroni = serve(cluster)) {
                String url = "jdbc:seclume:postgresql://127.0.0.1:1/app?user=app&tls=off"
                        + "&connectTimeout=1000&targetServerType=primary" + provider
                        + "&patroni=http://127.0.0.1:" + patroni.getLocalPort();
                assertThrows(SQLException.class,
                        () -> DriverManager.getConnection(url, new java.util.Properties()).close());
            }
            assertEquals(true, accepted.get() > 0, "the control did not reach the stand-in");
        } finally {
            Files.deleteIfExists(secret);
        }
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
