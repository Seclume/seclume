package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.tls.TestCertificates;

/**
 * A Vault login at its edges: a renewal that grants exactly half of the TTL
 * and one that grants a second less, a renewal Vault refuses, an empty
 * namespace, the headers of a renewal and of a revocation, a target of exactly
 * the token's length, forgetting a token twice, the scopes a login holds and
 * wipes, the ends of printable ASCII in a role, and the roles and machine
 * fields the cloud logins require. Written against the mutants PIT left alive
 * in this package.
 *
 * <p>Isolated: the count of open secret scopes is the JVM's.
 */
@Isolated
class VaultLoginEdgesTest {

    private static final Instant START = Instant.parse("2026-11-01T12:00:00Z");

    private static TestCertificates certificates;
    private static SSLContext context;

    @BeforeAll
    static void anAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        context = FakeVaultServer.context(certificates);
    }

    @AfterAll
    static void removeIt() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    private static String login(String token, long ttl, boolean renewable) {
        return "{\"auth\":{\"client_token\":\"" + token + "\",\"lease_duration\":" + ttl
                + ",\"renewable\":" + renewable + "}}";
    }

    /** A fixed secret id that counts its closes. */
    static final class Counted implements SecretProvider {
        final AtomicInteger closes = new AtomicInteger();

        @Override
        public int writeSecret(MemorySegment target) {
            byte[] bytes = "secret-id".getBytes(StandardCharsets.US_ASCII);
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        }

        @Override
        public int maxSecretLength() {
            return 64;
        }

        @Override
        public void close() {
            closes.incrementAndGet();
        }
    }

    private static final class MovingClock extends Clock {
        private Instant now = START;

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private static VaultLogin approle(FakeVaultServer vault, String namespace, SecretProvider secretId, Clock clock) {
        return new VaultLogin(vault.address(), VaultLogin.Method.APPROLE, null, "role-id", secretId, namespace,
                false, 10_000, clock);
    }

    private static String read(SecretProvider provider) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            int length = provider.writeSecret(target);
            return new String(target.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
        }
    }

    // ------------------------------------------------------------ renewal

    @Test
    void aRenewalOfHalfTheTtlIsKeptAndOneSecondLessIsALogin() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/approle/login", 200, login("hvs.first", 600, true), login("hvs.second", 600, true))
                .on("POST", "/v1/auth/token/renew-self", 200, login("hvs.first", 300, true),
                        login("hvs.first", 299, true));
        MovingClock clock = new MovingClock();
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = approle(vault, null, new Counted(), clock)) {
            assertEquals("hvs.first", read(login));
            clock.advance(Duration.ofSeconds(300));
            assertEquals("hvs.first", read(login));
            assertEquals(1, vault.requests().size(), "exactly halfway is not yet due");
            clock.advance(Duration.ofSeconds(1));
            assertEquals("hvs.first", read(login), "300 of 600 seconds granted: kept");
            assertEquals(1, vault.requests("POST", "/v1/auth/approle/login").size());
            assertEquals(START.plusSeconds(301 + 300), login.credentialsValidUntil());
            clock.advance(Duration.ofSeconds(151));
            assertEquals("hvs.second", read(login), "299 of 600 seconds: not worth keeping, a new login");
            assertEquals(2, vault.requests("POST", "/v1/auth/approle/login").size());
            assertEquals(2, vault.requests("POST", "/v1/auth/token/renew-self").size());
        }
    }

    @Test
    void aRenewalVaultRefusesIsALogin() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/approle/login", 200, login("hvs.a", 600, true), login("hvs.b", 600, true))
                .on("POST", "/v1/auth/token/renew-self", 403, "{\"errors\":[\"permission denied\"]}");
        MovingClock clock = new MovingClock();
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = approle(vault, null, new Counted(), clock)) {
            assertEquals("hvs.a", read(login));
            clock.advance(Duration.ofSeconds(301));
            assertEquals("hvs.b", read(login));
            assertEquals(1, vault.requests("POST", "/v1/auth/token/renew-self").size());
            assertEquals(2, login.generation());
        }
    }

    // ------------------------------------------------------------ headers

    @Test
    void anEmptyNamespaceSendsNoNamespaceAndOnlyABodyHasAContentType() throws Exception {
        for (String namespace : new String[] {"", "team-a"}) {
            FakeVaultServer.Script script = new FakeVaultServer.Script()
                    .on("POST", "/v1/auth/approle/login", 200, login("hvs.a", 600, true))
                    .on("POST", "/v1/auth/token/renew-self", 200, login("hvs.a", 600, true))
                    .on("POST", "/v1/auth/token/revoke-self", 204, "");
            MovingClock clock = new MovingClock();
            List<FakeVaultServer.Request> requests;
            try (FakeVaultServer vault = new FakeVaultServer(context, script)) {
                try (VaultLogin login = approle(vault, namespace, new Counted(), clock)) {
                    read(login);
                    clock.advance(Duration.ofSeconds(301));
                    read(login);
                }
                requests = vault.requests();
            }
            assertEquals(3, requests.size(), requests.toString());
            String expected = namespace.isEmpty() ? null : namespace;
            for (FakeVaultServer.Request request : requests) {
                assertEquals(expected, request.header("X-Vault-Namespace"), namespace + ": " + request);
            }
            assertTrue(requests.get(1).is("POST", "/v1/auth/token/renew-self"));
            assertEquals("application/json", requests.get(1).header("Content-Type"));
            assertTrue(requests.get(2).is("POST", "/v1/auth/token/revoke-self"));
            assertNull(requests.get(2).header("Content-Type"), "a revocation has no body to describe");
            assertEquals("hvs.a", requests.get(2).header("X-Vault-Token"));
        }
    }

    // ------------------------------------------------------------ the token

    @Test
    void theTokenFitsATargetOfExactlyItsLength() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/approle/login", 200, login("hvs.twelve-ch", 600, false));
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = approle(vault, null, new Counted(), new MovingClock());
             Arena arena = Arena.ofConfined()) {
            assertEquals(13, login.writeSecret(arena.allocate(13)));
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                    () -> login.writeSecret(arena.allocate(12)));
            assertEquals("the Vault token is 13 bytes and does not fit into the 12 provided", e.getMessage());
        }
    }

    @Test
    void aLoginHoldsOneScopeAndWipesItWhenForgottenReplacedOrClosed() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/approle/login", 200, login("hvs.a", 600, false), login("hvs.b", 600, false),
                        login("hvs.c", 600, false))
                .on("POST", "/v1/auth/token/revoke-self", 204, "");
        MovingClock clock = new MovingClock();
        Counted secretId = new Counted();
        try (FakeVaultServer vault = new FakeVaultServer(context, script)) {
            long before = SecretScope.open();
            VaultLogin login = approle(vault, null, secretId, clock);
            assertDoesNotThrow(() -> login.forget(true), "nothing to forget yet");
            assertEquals("hvs.a", read(login));
            assertEquals(before + 1, SecretScope.open(), "the token");
            login.forget(true);
            assertEquals(before, SecretScope.open(), "forgotten: wiped");
            login.forget(true);
            assertEquals(before, SecretScope.open());
            assertEquals("hvs.b", read(login), "the next read logs in again");
            clock.advance(Duration.ofSeconds(301));
            assertEquals("hvs.c", read(login), "replaced by a new login");
            assertEquals(before + 1, SecretScope.open(), "the old token wiped when the new one came");
            login.close();
            assertEquals(before, SecretScope.open(), "closed: wiped");
            assertEquals(1, secretId.closes.get(), "and the secret id's source closed");
            login.close();
            assertEquals(1, secretId.closes.get(), "once");
            SecretUnavailableException closed = assertThrows(SecretUnavailableException.class, () -> read(login));
            assertEquals("this Vault login is closed", closed.getMessage());
        }
    }

    // ------------------------------------------------------------ roles

    @Test
    void aRoleIsPrintableAsciiToItsEnds() {
        Counted secretId = new Counted();
        assertDoesNotThrow(() -> new VaultLogin("https://127.0.0.1:8200", VaultLogin.Method.APPROLE, null, " role~",
                secretId, null, false, 1000).close());
        for (String wrong : new String[] {"role\u001f", "role\u007f", "röle"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> new VaultLogin("https://127.0.0.1:8200", VaultLogin.Method.APPROLE, null, wrong,
                            secretId, null, false, 1000));
            int at = wrong.equals("röle") ? 1 : 4;
            assertEquals("a Vault role name or role id is printable ASCII; this one has a character outside it at "
                    + at, e.getMessage());
        }
    }

    @Test
    void theCloudLoginsThatNeedARoleSaySo() {
        for (String role : new String[] {null, "", "  "}) {
            IllegalArgumentException gcp = assertThrows(IllegalArgumentException.class,
                    () -> VaultLogin.gcp("https://127.0.0.1:8200", null, role, new Counted(), null, false, 1000,
                            Clock.systemUTC()));
            assertEquals("a gcp login needs auth-role, the Vault role to log in as", gcp.getMessage());
            IllegalArgumentException azure = assertThrows(IllegalArgumentException.class,
                    () -> VaultLogin.azure("https://127.0.0.1:8200", null, role, new Counted(),
                            () -> Map.of(), null, false, 1000, Clock.systemUTC()));
            assertEquals("a azure login needs auth-role, the Vault role to log in as", azure.getMessage());
        }
    }

    @Test
    void configuredAzureMachineFieldsArePrintableAscii() {
        assertEquals("vm-1", VaultLogin.azureVm("sub", "rg", "vm-1", null, "127.0.0.1", 1).get().get("vm_name"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> VaultLogin.azureVm("sub", "rg", "vm\u0001", null, "127.0.0.1", 1));
        assertEquals("a value for a Vault login is printable ASCII; this one has a character outside it at 2",
                e.getMessage());
        assertThrows(IllegalArgumentException.class,
                () -> VaultLogin.azureVm("sub\u007f", "rg", null, "set", "127.0.0.1", 1));
    }
}
