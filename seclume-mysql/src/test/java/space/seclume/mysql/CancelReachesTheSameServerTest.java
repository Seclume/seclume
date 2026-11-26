package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;

/**
 * {@code KILL QUERY <id>} runs on a second connection to the configured
 * host. Behind a load balancer that connection can reach another backend,
 * where the same id may be somebody else's session of the same user - and
 * their statement would be stopped. The cancellation now asks the second
 * connection which server it is on, and kills nothing where it is not the
 * session's own.
 */
@Timeout(60)
class CancelReachesTheSameServerTest {

    private static final String USER = "seclume_test";
    private static final String PASSWORD = "ein Testpasswort";

    private static SecretProvider secret() {
        byte[] bytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        return new CallbackSecretProvider(256, target -> {
            for (int i = 0; i < bytes.length; i++) {
                target.set(ValueLayout.JAVA_BYTE, i, bytes[i]);
            }
            return bytes.length;
        });
    }

    /** One address in front of two backends: the first connection to one, every later one to the other. */
    private static final class LoadBalancer implements AutoCloseable {
        final ServerSocket socket = new ServerSocket(0, 4, InetAddress.getLoopbackAddress());
        final AtomicInteger connections = new AtomicInteger();

        LoadBalancer(int first, int then) throws IOException {
            Thread.ofVirtual().start(() -> {
                while (!socket.isClosed()) {
                    try {
                        Socket client = socket.accept();
                        int backend = connections.getAndIncrement() == 0 ? first : then;
                        Socket server = new Socket(InetAddress.getLoopbackAddress(), backend);
                        pipe(client, server);
                        pipe(server, client);
                    } catch (IOException closed) {
                        return;
                    }
                }
            });
        }

        private static void pipe(Socket from, Socket to) {
            Thread.ofVirtual().start(() -> {
                try (InputStream in = from.getInputStream(); OutputStream out = to.getOutputStream()) {
                    in.transferTo(out);
                } catch (IOException ended) {
                    // one side went away
                } finally {
                    try {
                        to.close();
                        from.close();
                    } catch (IOException ignored) {
                        // closing either way
                    }
                }
            });
        }

        int port() {
            return socket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    /** A statement held on {@code a}, cancelled through a balancer that sends the KILL to {@code b}. */
    private static void cancelThroughTheBalancer(FakeMySqlServer a, FakeMySqlServer b,
            CancelResult result) throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        a.holdQueriesUntil(release);
        try (LoadBalancer balancer = new LoadBalancer(a.port(), b.port());
             MySession session = MySession.open(new MySession.Settings("127.0.0.1",
                     balancer.port(), "testdb", USER, secret()).allowingLegacyHash())) {
            Thread running = Thread.ofVirtual().start(() -> {
                try {
                    session.execute("select sleep(60)");
                } catch (SQLException ignored) {
                    // answered once let go
                }
            });
            assertTrue(a.arrived.await(10, TimeUnit.SECONDS), "the statement never arrived");
            try {
                session.cancel();
            } catch (SQLException refused) {
                result.refused = refused;
            } finally {
                release.countDown();
                running.join(10_000);
            }
        }
    }

    private static final class CancelResult {
        SQLException refused;
    }

    @Test
    void aKillThatReachesAnotherServerIsNotSent() throws Exception {
        try (FakeMySqlServer a = new FakeMySqlServer(USER, PASSWORD).identity("db-1:3306:11").start();
             FakeMySqlServer b = new FakeMySqlServer(USER, PASSWORD).identity("db-2:3306:12").start()) {
            CancelResult result = new CancelResult();
            cancelThroughTheBalancer(a, b, result);
            assertTrue(result.refused != null, "the cancellation claimed to have worked");
            assertEquals("0A000", result.refused.getSQLState());
            assertTrue(result.refused.getMessage().contains("another server"),
                    result.refused.getMessage());
            assertFalse(b.received().stream().anyMatch(sql -> sql.startsWith("kill")),
                    "a KILL QUERY reached the other server: " + b.received());
        }
    }

    @Test
    void onTheSameServerTheKillGoesOut() throws Exception {
        // Both backends say they are one server: the balancer had no choice to make.
        try (FakeMySqlServer a = new FakeMySqlServer(USER, PASSWORD).identity("db-1:3306:11").start();
             FakeMySqlServer b = new FakeMySqlServer(USER, PASSWORD).identity("db-1:3306:11").start()) {
            CancelResult result = new CancelResult();
            cancelThroughTheBalancer(a, b, result);
            assertEquals(null, result.refused, "refused on the same server");
            List<String> kills = b.received().stream().filter(sql -> sql.startsWith("kill")).toList();
            assertEquals(1, kills.size(), "expected one KILL QUERY: " + b.received());
            assertTrue(kills.get(0).startsWith("kill query "), kills.get(0));
        }
    }
}
