package space.seclume.grpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.ref.Reference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.grpc.CallCredentials;
import io.grpc.CallOptions;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.ClientCalls;

import space.seclume.tck.NoSecretInHeap;

/**
 * The gRPC OkHttp transport over seclume's TLS: the call credentials hold a
 * placeholder, and the server - another process - sees the token.
 */
class GrpcTest {

    @TempDir
    static Path directory;

    static Process server;
    static ManagedChannel channel;
    static CallCredentials bearer;

    @BeforeAll
    static void start() throws Exception {
        Path script = directory.resolve("secrets.sh");
        Files.writeString(script, String.join("\n", "set -e", "cd '" + directory + "'",
                "openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2"
                        + " -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null",
                "head -c 48 /dev/urandom | base64 | tr -d '\\n/+=' > token", ""));
        assertEquals(0, new ProcessBuilder("/bin/sh", script.toString()).start().waitFor());
        server = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java")
                .toString(), "-cp", System.getProperty("java.class.path"),
                GrpcServerProcess.class.getName(), directory.toString())
                .redirectErrorStream(true).redirectOutput(directory.resolve("server.log").toFile())
                .start();
        Path port = directory.resolve("port");
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (!Files.exists(port)) {
            assertTrue(server.isAlive() && System.nanoTime() < deadline, "the server did not start");
            Thread.sleep(50);
        }
        channel = SeclumeGrpc.channel("localhost", Integer.parseInt(Files.readString(port).trim()),
                "tlsRootCert=" + directory.resolve("cert.pem")).build();
        bearer = SeclumeGrpc.bearer("provider=file&path=" + directory.resolve("token"));
    }

    @AfterAll
    static void stop() throws Exception {
        if (channel != null) {
            channel.shutdownNow().awaitTermination(10, TimeUnit.SECONDS);
        }
        if (server != null) {
            server.destroy();
        }
    }

    private static String call(CallCredentials credentials, String request) {
        return ClientCalls.blockingUnaryCall(channel, Echo.METHOD,
                CallOptions.DEFAULT.withCallCredentials(credentials), request);
    }

    @Test
    void bearerTokenOnManyCalls() {
        // the client indexes its headers and refers to them afterwards: every call must hold
        for (int i = 0; i < 20; i++) {
            assertEquals("ok hello " + i, call(bearer, "hello " + i));
        }
        // a message that happens to hold a placeholder is sent as it is
        String note = "x".repeat(100_000);
        assertEquals("ok " + note, call(bearer, note));
    }

    /** Each call's header block with the token is a SecretUse event: h2, header. */
    @Test
    void eachCallIsRecorded() throws Exception {
        var events = space.seclume.tck.Recorded.during(() -> {
            call(bearer, "one");
            call(bearer, "two");
        }, "space.seclume.SecretUse");
        assertEquals(2, events.size(), events.toString());
        assertEquals("h2", events.get(0).getString("kind"));
    }

    @Test
    void apiKeyHeader() {
        CallCredentials apiKey = SeclumeGrpc.header("x-api-key", "provider=file&path="
                + directory.resolve("token"));
        assertEquals("ok key", call(apiKey, "key"));
    }

    @Test
    void aHeaderBlockLargerThanAFrame() {
        CallCredentials large = new CallCredentials() {
            @Override
            public void applyRequestMetadata(RequestInfo info, Executor executor,
                                             MetadataApplier applier) {
                bearer.applyRequestMetadata(info, executor, new MetadataApplier() {
                    @Override
                    public void apply(Metadata headers) {
                        headers.put(Metadata.Key.of("x-padding", Metadata.ASCII_STRING_MARSHALLER),
                                "p".repeat(40_000));
                        applier.apply(headers);
                    }

                    @Override
                    public void fail(Status status) {
                        applier.fail(status);
                    }
                });
            }
        };
        assertEquals("ok big", call(large, "big"));
    }

    @Test
    void aWrongTokenIsRefusedByTheServer() {
        CallCredentials wrong = new CallCredentials() {
            @Override
            public void applyRequestMetadata(RequestInfo info, Executor executor,
                                             MetadataApplier applier) {
                Metadata headers = new Metadata();
                headers.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER),
                        "Bearer guessed");
                applier.apply(headers);
            }
        };
        StatusRuntimeException refused = assertThrows(StatusRuntimeException.class,
                () -> call(wrong, "no"));
        assertEquals(Status.Code.UNAUTHENTICATED, refused.getStatus().getCode());
    }

    @Test
    void aRotatedTokenIsPickedUp() throws Exception {
        Path token = directory.resolve("token");
        String before = Files.readString(token);
        try {
            Path next = directory.resolve("token.next");
            assertEquals(0, new ProcessBuilder("/bin/sh", "-c",
                    "head -c 48 /dev/urandom | base64 | tr -d '\\n/+=' > token.next")
                    .directory(directory.toFile()).start().waitFor());
            Files.move(next, token, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            assertEquals("ok rotated", call(bearer, "rotated"));
        } finally {
            Files.writeString(token, before);
            Reference.reachabilityFence(before);
        }
    }

    @Test
    void theTokenIsNotOnTheHeap() throws Exception {
        for (int i = 0; i < 5; i++) {
            call(bearer, "call " + i);
        }
        NoSecretInHeap.assertAbsent(directory.resolve("token"));
        String leaked = Files.readString(directory.resolve("token")); // the control
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(directory.resolve("token")));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(leaked);
    }
}
