package space.seclume.nats;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.ref.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import io.nats.client.Connection;
import io.nats.client.Message;
import io.nats.client.Nats;
import io.nats.client.Options;
import io.nats.client.Subscription;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.Recorded;

/**
 * End-to-end proof against {@link FakeNatsServerMain} in a separate JVM:
 * connects with {@code auth=nkey}, {@code auth=creds}, {@code user=}
 * (password), and {@code auth=token} over seclume's own TLS 1.3, publishes and
 * receives messages, checks JFR {@code SecretUse} and {@code Signature}
 * events, verifies that a password set on {@link Options} is refused, and
 * proves that none of the secrets - neither the Base32 NKey seeds, the raw
 * 32-byte Ed25519 seeds, the password, nor the token - is on this JVM's heap.
 */
@Timeout(300)
class NoCredentialOnTheHeapTest {

    @Test
    @SuppressWarnings("try")
    void nkeyCredsPasswordAndTokenLeaveNoSecretOnTheHeap() throws Exception {
        Path directory = Files.createTempDirectory("seclume-nats-proof");
        Process server = new ProcessBuilder(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED",
                "-cp", System.getProperty("java.class.path"),
                FakeNatsServerMain.class.getName(),
                directory.toString()))
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
        try (BufferedReader out = new BufferedReader(new InputStreamReader(
                server.getInputStream(), StandardCharsets.UTF_8))) {
            String ready = out.readLine();
            assertTrue(ready != null && ready.startsWith("READY "), "server said: " + ready);
            String[] parts = ready.split(" ");
            String port = parts[1];
            String pin = parts[2];
            String base = "tls://localhost:" + port + "?tlsPin=" + pin;

            // 1. NKey challenge-response login
            String nkeyUrl = base + "&auth=nkey&provider=file&path="
                    + slashes(directory.resolve("user.nk"));
            var nkeyEvents = Recorded.during(() -> {
                try (Connection nc = SeclumeNats.connect(nkeyUrl)) {
                    Subscription sub = nc.subscribe("orders.nkey");
                    nc.publish("orders.nkey", "hello-nkey".getBytes(StandardCharsets.UTF_8));
                    nc.flush(Duration.ofSeconds(5));
                    Message msg = sub.nextMessage(Duration.ofSeconds(5));
                    assertNotNull(msg);
                    assertEquals("hello-nkey", new String(msg.getData(), StandardCharsets.UTF_8));
                }
            }, "space.seclume.SecretUse", "space.seclume.Signature");
            assertTrue(nkeyEvents.stream().anyMatch(e ->
                    "space.seclume.SecretUse".equals(e.getEventType().getName())
                            && "nats".equals(e.getString("kind"))
                            && "nkey".equals(e.getString("mechanism"))));
            assertTrue(nkeyEvents.stream().anyMatch(e ->
                    "space.seclume.Signature".equals(e.getEventType().getName())
                            && "Ed25519".equals(e.getString("algorithm"))
                            && e.getBoolean("succeeded")));

            // 2. .creds (User JWT + NKey seed) login
            String credsUrl = base + "&auth=creds&provider=file&path="
                    + slashes(directory.resolve("user.creds"));
            try (Connection nc = SeclumeNats.connect(credsUrl)) {
                Subscription sub = nc.subscribe("orders.creds");
                nc.publish("orders.creds", "hello-creds".getBytes(StandardCharsets.UTF_8));
                nc.flush(Duration.ofSeconds(5));
                Message msg = sub.nextMessage(Duration.ofSeconds(5));
                assertNotNull(msg);
                assertEquals("hello-creds", new String(msg.getData(), StandardCharsets.UTF_8));
            }

            // 3. Password login rewritten in CONNECT from native memory
            String passwordUrl = base + "&user=orders&provider=file&path="
                    + slashes(directory.resolve("password.txt"));
            var pwEvents = Recorded.during(() -> {
                try (Connection nc = SeclumeNats.connect(passwordUrl)) {
                    Subscription sub = nc.subscribe("orders.pw");
                    nc.publish("orders.pw", "hello-pw".getBytes(StandardCharsets.UTF_8));
                    nc.flush(Duration.ofSeconds(5));
                    Message msg = sub.nextMessage(Duration.ofSeconds(5));
                    assertNotNull(msg);
                    assertEquals("hello-pw", new String(msg.getData(), StandardCharsets.UTF_8));
                }
            }, "space.seclume.SecretUse");
            assertEquals(1, pwEvents.size());
            assertEquals("nats", pwEvents.get(0).getString("kind"));
            assertEquals("password", pwEvents.get(0).getString("mechanism"));

            // 4. Token login rewritten in CONNECT from native memory
            String tokenUrl = base + "&auth=token&provider=file&path="
                    + slashes(directory.resolve("token.txt"));
            try (Connection nc = SeclumeNats.connect(tokenUrl)) {
                Subscription sub = nc.subscribe("orders.tok");
                nc.publish("orders.tok", "hello-tok".getBytes(StandardCharsets.UTF_8));
                nc.flush(Duration.ofSeconds(5));
                Message msg = sub.nextMessage(Duration.ofSeconds(5));
                assertNotNull(msg);
                assertEquals("hello-tok", new String(msg.getData(), StandardCharsets.UTF_8));
            }

            // 5. Refuses a password set directly on Options.Builder
            Options.Builder overridden = SeclumeNats.configure(new Options.Builder(), passwordUrl);
            overridden.userInfo("orders".toCharArray(), "heap-password".toCharArray());
            Options badOptions = overridden.build();
            SeclumeNatsDataPort.register(badOptions, NatsSettings.of(passwordUrl));
            assertThrows(Exception.class, () -> Nats.connect(badOptions));

            server.getOutputStream().close();
            assertTrue(server.waitFor(30, TimeUnit.SECONDS));
            String summary = out.readLine();
            assertEquals("AUTHENTICATED 4", summary);

            for (String secretFile : List.of(
                    "user.nk", "user-seed.bin",
                    "creds-seed.txt", "creds-seed.bin",
                    "password.txt", "token.txt")) {
                NoSecretInHeap.assertAbsent(directory.resolve(secretFile));
            }

            // Negative control: reading the NKey seed into a String on the heap must be detected.
            String leaked = Files.readString(directory.resolve("user.nk")); // seclume-allow: the control, put on the heap on purpose
            AssertionError found = assertThrows(AssertionError.class,
                    () -> NoSecretInHeap.assertAbsent(directory.resolve("user.nk")));
            assertTrue(found.getMessage().contains("the secret is on the heap"),
                    found.getMessage());
            Reference.reachabilityFence(leaked);
        } finally {
            server.destroyForcibly();
            try (var files = Files.list(directory)) {
                for (Path file : files.toList()) {
                    Files.deleteIfExists(file);
                }
            }
            Files.deleteIfExists(directory);
        }
    }

    private static String slashes(Path path) {
        return path.toString().replace('\\', '/');
    }
}
