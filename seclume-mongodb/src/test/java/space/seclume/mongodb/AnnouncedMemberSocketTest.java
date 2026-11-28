package space.seclume.mongodb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.mongodb.internal.MemberHosts;

/**
 * The official driver connects to every member a hello names, and seclume's
 * socket logs in to each. A host outside the seeds' domains - brought in by
 * a compromised member or an {@code rs.reconfig}, with a valid public
 * certificate - gets no connection at all, so no SCRAM proof, no AWS
 * signature and no OIDC token.
 */
@Timeout(30)
class AnnouncedMemberSocketTest {

    @TempDir
    Path tempDir;

    /** Counts the connections that reach it, and closes them. */
    private static final class Counting implements AutoCloseable {
        final ServerSocket socket = new ServerSocket(0, 5, InetAddress.getLoopbackAddress());
        final AtomicInteger accepted = new AtomicInteger();

        Counting() throws IOException {
            Thread.ofVirtual().start(() -> {
                while (!socket.isClosed()) {
                    try {
                        socket.accept().close();
                        accepted.incrementAndGet();
                    } catch (IOException closed) {
                        return;
                    }
                }
            });
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    private MongoUrl url(String hosts) throws IOException {
        Path secret = tempDir.resolve("secret.pw");
        Files.writeString(secret, "correct-password-42");
        return MongoUrl.parse("mongodb://orders@" + hosts + "/?authSource=admin&provider=file&path="
                + secret.toString().replace('\\', '/'));
    }

    /** {@code name}, resolving to the loopback address - a DNS answer the test controls. */
    private static InetSocketAddress named(String name, int port) throws IOException {
        return new InetSocketAddress(
                InetAddress.getByAddress(name, InetAddress.getLoopbackAddress().getAddress()), port);
    }

    @Test
    void anAnnouncedHostOutsideTheSeedsGetsNoConnection() throws Exception {
        try (Counting server = new Counting();
             SeclumeMongoSocket socket = new SeclumeMongoSocket(url("seed1.a.org:27017"))) {
            IOException refused = assertThrows(IOException.class,
                    () -> socket.connect(named("evil.b.org", server.socket.getLocalPort()), 2000));
            assertTrue(refused.getMessage().contains("outside the domains of the seeds"),
                    refused.getMessage());
            Thread.sleep(200);                  // a connection would have been counted by now
            assertEquals(0, server.accepted.get(), "a connection was made to the announced host");
        }
    }

    /** Past the check, then refused by a server that is no MongoDB: the connection was made. */
    private static void connectedTo(Counting server, MongoUrl url, InetSocketAddress address)
            throws Exception {
        try (SeclumeMongoSocket socket = new SeclumeMongoSocket(url)) {
            IOException failed = assertThrows(IOException.class, () -> socket.connect(address, 2000));
            assertFalse(String.valueOf(failed.getMessage()).contains("outside the domains"),
                    failed.getMessage());
        }
        long deadline = System.nanoTime() + 2_000_000_000L;
        while (server.accepted.get() == 0 && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertEquals(1, server.accepted.get(), "the seed itself was not connected to");
    }

    @Test
    void aSeedOnAnotherPortIsConnectedTo() throws Exception {
        try (Counting server = new Counting()) {
            connectedTo(server, url("localhost:27017"), named("localhost", server.socket.getLocalPort()));
        }
    }

    @Test
    void aSeedWrittenAsAnAddressIsMatchedByTheAddress() throws Exception {
        // The official driver resolves the seed itself; the host string it
        // hands over can then be a reverse lookup's name, not the address.
        try (Counting server = new Counting()) {
            connectedTo(server, url("127.0.0.1:27017"), named("localhost", server.socket.getLocalPort()));
        }
    }

    @Test
    void theRuleOfTheSeedsDomain() {
        List<String> seeds = MemberHosts.seedsOf("mongodb://db1.corp.example:27017,"
                + "db2.corp.example:27018/?replicaSet=rs0");
        assertEquals(List.of("db1.corp.example", "db2.corp.example"), seeds);
        assertTrue(MemberHosts.mayJoin("DB3.corp.example", seeds, List.of()));
        assertFalse(MemberHosts.mayJoin("evil.example", seeds, List.of()));
        assertFalse(MemberHosts.mayJoin("corp.example.evil.example", seeds, List.of()));
        // A literal address admits only itself.
        assertFalse(MemberHosts.mayJoin("10.0.0.2", List.of("10.0.0.1"), List.of()));
    }

    @Test
    void anAllowedSuffixAdmitsItsDomain() {
        List<String> seeds = List.of("seed1.a.org");
        assertFalse(MemberHosts.mayJoin("evil.b.org", seeds, List.of()));
        for (String written : List.of("*.b.org", ".b.org", "b.org")) {
            assertTrue(MemberHosts.mayJoin("evil.b.org", seeds,
                    MemberHosts.suffixes(written)), written);
        }
        assertFalse(MemberHosts.mayJoin("evil.notb.org", seeds,
                MemberHosts.suffixes("*.b.org")));
    }
}
