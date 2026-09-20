package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tls.TestCertificates;

/**
 * The Vault provider against an HTTPS server that answers like Vault.
 *
 * <p>Not a mock of the provider and not a stub of the HTTP layer: a real
 * {@code SSLServerSocket} with a real certificate, so the whole route is
 * exercised - TLS, the HTTP/1.1 request this library writes by hand, the
 * response parsing, and the JSON reader. A mock would have proved that the
 * code calls the methods it calls.
 *
 * <p>What it cannot cover is Vault's own behaviour, and that is said rather
 * than papered over: the answers here are recorded shapes, and if Vault
 * changes them this test will keep passing. What it does pin down is
 * everything on this side of the wire, including the two things that would
 * otherwise be discovered in production - that a dynamic credential is
 * <b>not</b> fetched once per connection, and that its expiry is reported.
 */
@Timeout(120)
class VaultSecretProviderTest {

    private static TestCertificates certificates;
    private static SSLContext serverContext;

    @BeforeAll
    static void anAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued vault = certificates.issue("vault",
                "san=dns:vault.example.com,ip:127.0.0.1", "eku=serverAuth");

        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(vault.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        serverContext = SSLContext.getInstance("TLSv1.3");
        serverContext.init(keys.getKeyManagers(), null, null);
    }

    @AfterAll
    static void removeIt() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    // ---------------------------------------------------------- the server --

    /** Answers a fixed body to every request and records what it was asked. */
    private static final class FakeVault implements AutoCloseable {

        private final SSLServerSocket socket;
        private final Thread thread;
        private final List<String> requests = new CopyOnWriteArrayList<>();
        private final AtomicInteger served = new AtomicInteger();
        private final List<String> bodies;
        private final int status;
        private volatile boolean stopped;

        FakeVault(int status, String... bodies) throws IOException {
            this.status = status;
            this.bodies = List.of(bodies);
            this.socket = (SSLServerSocket) serverContext.getServerSocketFactory()
                    .createServerSocket(0, 4, InetAddress.getLoopbackAddress());
            this.socket.setSoTimeout(30_000);
            this.thread = new Thread(this::serve, "fake-vault");
            this.thread.setDaemon(true);
            this.thread.start();
        }

        private void serve() {
            while (!stopped) {
                try (SSLSocket accepted = (SSLSocket) socket.accept()) {
                    accepted.setSoTimeout(30_000);
                    requests.add(readRequest(accepted.getInputStream()));
                    int index = Math.min(served.getAndIncrement(), bodies.size() - 1);
                    byte[] body = bodies.get(index).getBytes(StandardCharsets.UTF_8);

                    OutputStream out = accepted.getOutputStream();
                    out.write(("HTTP/1.1 " + status + " \r\n"
                            + "Content-Type: application/json\r\n"
                            + "Content-Length: " + body.length + "\r\n"
                            + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    out.write(body);
                    out.flush();
                } catch (Exception stoppedOrFailed) {
                    if (stopped) {
                        return;
                    }
                }
            }
        }

        /** Up to the blank line - enough to assert on the path and the headers. */
        private static String readRequest(InputStream in) throws IOException {
            StringBuilder text = new StringBuilder();
            int b;
            while ((b = in.read()) >= 0) {
                text.append((char) b);
                if (text.length() >= 4 && text.indexOf("\r\n\r\n", text.length() - 4) >= 0) {
                    break;
                }
            }
            return text.toString();
        }

        int port() {
            return socket.getLocalPort();
        }

        int served() {
            return served.get();
        }

        @Override
        public void close() throws IOException {
            stopped = true;
            socket.close();
        }
    }

    private static SecretProvider tokenProvider(String token) {
        byte[] bytes = token.getBytes(StandardCharsets.US_ASCII);
        return new CallbackSecretProvider(bytes.length, target -> {
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
    }

    private static String read(SecretProvider provider) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            int length = provider.writeSecret(target);
            byte[] bytes = new byte[length];
            MemorySegment.copy(target, ValueLayout.JAVA_BYTE, 0, bytes, 0, length);
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    private static VaultSecretProvider provider(FakeVault vault, String path, Clock clock) {
        // verify=false because the certificate is signed by an authority that
        // exists for the length of this run and is in no trust store. The
        // certificate check itself has its own test below.
        return new VaultSecretProvider("https://127.0.0.1:" + vault.port(), path, "password",
                tokenProvider("hvs.testtoken"), null, false, 10_000, 256, clock);
    }

    // ----------------------------------------------------------- the cases --

    @Test
    void aStaticKvV2SecretIsRead() throws Exception {
        String answer = "{\"request_id\":\"1\",\"lease_duration\":0,"
                + "\"data\":{\"data\":{\"password\":\"hunter2\"},"
                + "\"metadata\":{\"version\":3}}}";

        try (FakeVault vault = new FakeVault(200, answer);
             VaultSecretProvider provider = provider(vault, "secret/data/app", Clock.systemUTC())) {

            assertEquals("hunter2", read(provider));
            assertNull(provider.credentialsValidUntil(), "a KV secret has no lease");

            String request = vault.requests.get(0);
            assertTrue(request.startsWith("GET /v1/secret/data/app HTTP/1.1"), request);
            assertTrue(request.contains("X-Vault-Token: hvs.testtoken"), request);
        }
    }

    @Test
    void aDynamicDatabaseCredentialIsReadWithItsLease() throws Exception {
        Instant now = Instant.parse("2026-09-20T12:00:00Z");
        String answer = "{\"lease_id\":\"database/creds/app/x\",\"renewable\":true,"
                + "\"lease_duration\":3600,"
                + "\"data\":{\"username\":\"v-token-app-1\",\"password\":\"A1a-generated\"}}";

        try (FakeVault vault = new FakeVault(200, answer);
             VaultSecretProvider provider = provider(vault, "database/creds/app",
                     Clock.fixed(now, ZoneOffset.UTC))) {

            assertEquals("A1a-generated", read(provider));
            assertEquals(now.plusSeconds(3600), provider.credentialsValidUntil());
        }
    }

    /**
     * The one that matters most, and the one a naive provider gets wrong.
     *
     * <p>Every request to {@code database/creds} creates a new database user
     * with a lease of its own. A provider that fetched on each call - which is
     * what the interface invites, since it is asked once per physical
     * connection - would leave a pool of sixteen trailing hundreds of roles
     * behind it, all of them valid until their leases ran out.
     */
    @Test
    void aDynamicCredentialIsNotFetchedOncePerConnection() throws Exception {
        String answer = "{\"lease_duration\":3600,\"data\":{\"password\":\"once\"}}";

        try (FakeVault vault = new FakeVault(200, answer);
             VaultSecretProvider provider = provider(vault, "database/creds/app",
                     Clock.fixed(Instant.parse("2026-09-20T12:00:00Z"), ZoneOffset.UTC))) {

            for (int connection = 0; connection < 20; connection++) {
                assertEquals("once", read(provider));
            }
            assertEquals(1, vault.served(), "Vault was asked more than once");
        }
    }

    /** Halfway through the lease it fetches again, and the new one is used. */
    @Test
    void itRefreshesHalfwayThroughTheLease() throws Exception {
        Instant start = Instant.parse("2026-09-20T12:00:00Z");
        MovingClock clock = new MovingClock(start);

        try (FakeVault vault = new FakeVault(200,
                "{\"lease_duration\":3600,\"data\":{\"password\":\"first\"}}",
                "{\"lease_duration\":3600,\"data\":{\"password\":\"second\"}}");
             VaultSecretProvider provider = provider(vault, "database/creds/app", clock)) {

            assertEquals("first", read(provider));

            clock.advance(Duration.ofMinutes(20));       // a third of the way
            assertEquals("first", read(provider), "too early to refresh");
            assertEquals(1, vault.served());

            clock.advance(Duration.ofMinutes(20));       // past halfway
            assertEquals("second", read(provider));
            assertEquals(2, vault.served());
            assertEquals(start.plus(Duration.ofMinutes(40)).plusSeconds(3600),
                    provider.credentialsValidUntil(), "the lease is the new one");
        }
    }

    /**
     * A long lease is refreshed no later than thirty seconds before it ends.
     *
     * <p>Half of twenty-four hours is twelve, and twelve hours of confidence
     * in a credential that may have been revoked is not a safety margin.
     */
    @Test
    void aVeryLongLeaseStillRefreshesNearItsEnd() throws Exception {
        MovingClock clock = new MovingClock(Instant.parse("2026-09-20T12:00:00Z"));

        try (FakeVault vault = new FakeVault(200,
                "{\"lease_duration\":60,\"data\":{\"password\":\"first\"}}",
                "{\"lease_duration\":60,\"data\":{\"password\":\"second\"}}");
             VaultSecretProvider provider = provider(vault, "database/creds/app", clock)) {

            assertEquals("first", read(provider));
            clock.advance(Duration.ofSeconds(25));       // before half of 60
            assertEquals("first", read(provider));
            clock.advance(Duration.ofSeconds(10));       // 35s in: past half, and inside 30s
            assertEquals("second", read(provider));
        }
    }

    @Test
    void aForbiddenAnswerSaysWhatToLookAt() throws Exception {
        try (FakeVault vault = new FakeVault(403, "{\"errors\":[\"permission denied\"]}");
             VaultSecretProvider provider = provider(vault, "secret/data/app",
                     Clock.systemUTC())) {

            SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                    () -> read(provider));
            assertTrue(refused.getMessage().contains("403"), refused.getMessage());
            assertTrue(refused.getMessage().contains("token"), refused.getMessage());
        }
    }

    @Test
    void anAnswerWithoutTheFieldSaysSo() throws Exception {
        try (FakeVault vault = new FakeVault(200, "{\"data\":{\"username\":\"app\"}}");
             VaultSecretProvider provider = provider(vault, "database/creds/app",
                     Clock.systemUTC())) {

            SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                    () -> read(provider));
            assertTrue(refused.getMessage().contains("password"), refused.getMessage());
        }
    }

    /**
     * The certificate is checked unless told otherwise.
     *
     * <p>Without this the {@code verify=false} in every other test here would
     * be proving that verification does not happen at all.
     */
    @Test
    void anUnknownCertificateIsRefusedWhenVerifyingIsOn() throws Exception {
        try (FakeVault vault = new FakeVault(200, "{\"data\":{\"password\":\"x\"}}")) {
            VaultSecretProvider provider = new VaultSecretProvider(
                    "https://127.0.0.1:" + vault.port(), "secret/data/app", "password",
                    tokenProvider("hvs.t"), null, true, 10_000, 256, Clock.systemUTC());

            SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                    () -> read(provider));
            assertNotNull(refused.getCause());
            provider.close();
        }
    }

    /** Plain http is refused at construction, not at the first fetch. */
    @Test
    void plainHttpIsRefusedOutright() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> new VaultSecretProvider("http://vault:8200", "secret/data/app", "password",
                        tokenProvider("t"), null, true, 1000, 256));
        assertTrue(refused.getMessage().contains("clear"), refused.getMessage());
    }

    /** The namespace header goes out when there is one. */
    @Test
    void anEnterpriseNamespaceIsSent() throws Exception {
        try (FakeVault vault = new FakeVault(200,
                "{\"data\":{\"data\":{\"password\":\"x\"}}}")) {
            try (VaultSecretProvider provider = new VaultSecretProvider(
                    "https://127.0.0.1:" + vault.port(), "secret/data/app", "password",
                    tokenProvider("hvs.t"), "team-a", false, 10_000, 256, Clock.systemUTC())) {

                assertEquals("x", read(provider));
                assertTrue(vault.requests.get(0).contains("X-Vault-Namespace: team-a"),
                        vault.requests.get(0));
            }
        }
    }

    /** Reachable through the ordinary configuration, like every other provider. */
    @Test
    void theRegistryBuildsIt(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        Path tokenFile = dir.resolve("token");
        Files.writeString(tokenFile, "hvs.fromfile");

        try (FakeVault vault = new FakeVault(200,
                "{\"data\":{\"data\":{\"password\":\"configured\"}}}")) {

            Map<String, String> settings = new LinkedHashMap<>();
            settings.put("provider", "vault");
            settings.put("address", "https://127.0.0.1:" + vault.port());
            settings.put("path", "secret/data/app");
            settings.put("verify", "false");
            settings.put("token-provider", "file");
            settings.put("token-path", tokenFile.toString());

            try (SecretProvider provider = SecretProviders.of(settings)) {
                assertEquals("configured", read(provider));
                assertTrue(vault.requests.get(0).contains("X-Vault-Token: hvs.fromfile"),
                        vault.requests.get(0));
            }
        }
    }

    /** No secret scope is left open, whichever way the fetch ends. */
    @Test
    void nothingIsLeftOpenOnFailure() throws Exception {
        long open = SecretScope.open();
        try (FakeVault vault = new FakeVault(500, "{\"errors\":[\"internal\"]}");
             VaultSecretProvider provider = provider(vault, "secret/data/app",
                     Clock.systemUTC())) {
            assertThrows(SecretUnavailableException.class, () -> read(provider));
        }
        assertEquals(open, SecretScope.open());
    }

    /** A clock the test moves by hand - no sleeping for a lease to age. */
    private static final class MovingClock extends Clock {

        private Instant now;

        MovingClock(Instant start) {
            this.now = start;
        }

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }

}
