package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.Segments;

/**
 * {@code provider=unix-socket}: an agent on a Unix domain socket answers with
 * the secret and closes the connection. A blocking read has no timeout of its
 * own, so an agent that kept the connection open after its answer - or never
 * answered - held the caller for ever; now the whole answer has to arrive
 * within {@code timeout-millis}.
 */
@Timeout(60)
class UnixSocketSecretProviderTest {

    @TempDir
    Path dir;

    /** What the agent does with one connection. */
    private interface Agent {
        void serve(SocketChannel client) throws Exception;
    }

    /** An agent on {@code socket} for one connection; the future fails if the agent did. */
    private CompletableFuture<Void> agent(Path socket, Agent agent) throws IOException {
        ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        server.bind(UnixDomainSocketAddress.of(socket));
        CompletableFuture<Void> done = new CompletableFuture<>();
        Thread.ofVirtual().start(() -> {
            try (server; SocketChannel client = server.accept()) {
                agent.serve(client);
                done.complete(null);
            } catch (Exception e) {
                done.completeExceptionally(e);
            }
        });
        return done;
    }

    private static void send(SocketChannel client, String text) throws IOException {
        ByteBuffer out = ByteBuffer.wrap(text.getBytes(StandardCharsets.UTF_8));
        while (out.hasRemaining()) {
            client.write(out);
        }
    }

    private static String read(SecretProvider provider) {
        try (SecretScope scope = SecretScope.fromProvider(provider)) {
            return new String(Segments.toBytes(scope.secret()), StandardCharsets.UTF_8);
        }
    }

    private static SecretUnavailableException refused(SecretProvider provider, long withinMillis) {
        long started = System.nanoTime();
        SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                () -> SecretScope.fromProvider(provider).close());
        long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
        assertTrue(took < withinMillis, "took " + took + " ms: " + e.getMessage());
        return e;
    }

    @Test
    void theAnswerUpToTheCloseIsTheSecret() throws Exception {
        Path socket = dir.resolve("agent.sock");
        agent(socket, client -> send(client, "agent-secret\n"));
        assertEquals("agent-secret", read(new UnixSocketSecretProvider(socket, null, 64, 5_000)));
    }

    @Test
    void theRequestLineGoesFirstAndTheAnswerMayComeInPieces() throws Exception {
        Path socket = dir.resolve("agent.sock");
        CompletableFuture<String> asked = new CompletableFuture<>();
        agent(socket, client -> {
            ByteBuffer in = ByteBuffer.allocate(64);
            client.read(in);
            asked.complete(new String(in.array(), 0, in.position(), StandardCharsets.UTF_8));
            send(client, "pie");
            Thread.sleep(200);
            send(client, "ces");
        });
        assertEquals("pieces", read(new UnixSocketSecretProvider(socket, "GET db\n", 64, 5_000)));
        assertEquals("GET db\n", asked.get(5, TimeUnit.SECONDS));
    }

    @Test
    void anAgentThatKeepsTheConnectionOpenIsRefusedAtTheTimeout() throws Exception {
        Path socket = dir.resolve("agent.sock");
        agent(socket, client -> {
            send(client, "agent-secret\n");
            Thread.sleep(30_000);
        });
        SecretUnavailableException e = refused(
                new UnixSocketSecretProvider(socket, null, 64, 500), 10_000);
        assertTrue(e.getMessage().contains("did not answer and close the connection within 500 ms"),
                e.getMessage());
        assertTrue(!e.getMessage().contains("agent-secret"), e.getMessage());
    }

    @Test
    void anAgentThatNeverAnswersIsRefusedAtTheTimeout() throws Exception {
        Path socket = dir.resolve("agent.sock");
        agent(socket, client -> Thread.sleep(30_000));
        SecretUnavailableException e = refused(
                new UnixSocketSecretProvider(socket, null, 64, 500), 10_000);
        assertTrue(e.getMessage().contains("within 500 ms"), e.getMessage());
    }

    @Test
    void oneByteMoreThanTheMaximumIsRefused() throws Exception {
        Path socket = dir.resolve("agent.sock");
        agent(socket, client -> send(client, "12345678X"));
        SecretUnavailableException e = refused(
                new UnixSocketSecretProvider(socket, null, 8, 5_000), 10_000);
        assertTrue(e.getMessage().contains("more than the configured 8 bytes"), e.getMessage());
        Path exact = dir.resolve("exact.sock");
        agent(exact, client -> send(client, "12345678"));
        assertEquals("12345678", read(new UnixSocketSecretProvider(exact, null, 8, 5_000)));
    }

    @Test
    void anAgentThatSendsNothingSaysSo() throws Exception {
        Path socket = dir.resolve("agent.sock");
        agent(socket, client -> { });
        SecretUnavailableException e = refused(
                new UnixSocketSecretProvider(socket, null, 64, 5_000), 10_000);
        assertTrue(e.getMessage().contains("sent nothing"), e.getMessage());
    }

    @Test
    void theTimeoutIsASettingOfItsOwn() throws Exception {
        Path socket = dir.resolve("agent.sock");
        agent(socket, client -> Thread.sleep(30_000));
        SecretProvider provider = SecretProviders.of(Map.of("provider", "unix-socket",
                "path", socket.toString(), "timeout-millis", "300"));
        assertTrue(refused(provider, 10_000).getMessage().contains("within 300 ms"));
        assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(Map.of(
                "provider", "unix-socket", "path", socket.toString(), "timeout-millis", "0")));
        assertThrows(IllegalArgumentException.class,
                () -> new UnixSocketSecretProvider(socket, null, 64, 0));
    }
}
