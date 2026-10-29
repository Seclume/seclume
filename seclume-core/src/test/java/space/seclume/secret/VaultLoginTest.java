package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.tls.TestCertificates;

/**
 * Logging in to Vault for a token - Kubernetes, JWT and AppRole - against
 * {@link FakeVaultServer}: what goes into the login request, how the token is
 * used, renewed, replaced and revoked, and how its end bounds the database
 * credential it fetched. The heap half of the claim is
 * {@link VaultLoginHeapTest}, which needs Vault in another JVM.
 */
@Timeout(120)
@org.junit.jupiter.api.parallel.Isolated
class VaultLoginTest {

    private static final String JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeXN0ZW06c2EifQ.c2ln";
    private static final Instant START = Instant.parse("2026-10-28T12:00:00Z");

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

    // ------------------------------------------------------------- helpers --

    private static String login(String token, long ttl, boolean renewable) {
        return "{\"request_id\":\"r\",\"lease_duration\":0,\"auth\":{\"client_token\":\"" + token
                + "\",\"accessor\":\"acc\",\"policies\":[\"app\"],\"lease_duration\":" + ttl
                + ",\"renewable\":" + renewable + "}}";
    }

    private static String creds(String user, String password, long lease) {
        return "{\"lease_id\":\"database/creds/app/" + user + "\",\"renewable\":true,"
                + "\"lease_duration\":" + lease + ",\"data\":{\"username\":\"" + user
                + "\",\"password\":\"" + password + "\"}}";
    }

    /** A source whose content the test can change, as the kubelet rotates a projected token. */
    private static SecretProvider fixed(AtomicReference<String> value) {
        return new CallbackSecretProvider(16_384, target -> {
            byte[] bytes = value.get().getBytes(StandardCharsets.UTF_8);
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
    }

    private static SecretProvider fixed(String value) {
        return fixed(new AtomicReference<>(value));
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

    private static VaultLogin login(FakeVaultServer vault, VaultLogin.Method method, String mount,
            String role, SecretProvider credential, Clock clock) {
        // verify=false: the CA exists for this run only. Certificate checking
        // is VaultSecretProviderTest's.
        return new VaultLogin(vault.address(), method, mount, role, credential, null, false,
                10_000, clock);
    }

    private static VaultSecretProvider provider(FakeVaultServer vault, String path,
            SecretProvider token, Clock clock) {
        return new VaultSecretProvider(vault.address(), path, "password", token, null, false,
                10_000, 256, clock);
    }

    private static final class MovingClock extends Clock {
        private Instant now;

        MovingClock(Instant start) {
            this.now = start;
        }

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

    // -------------------------------------------------------- the requests --

    @Test
    void aKubernetesLoginSendsTheRoleAndTheJwtAndTheTokenIsUsed() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/kubernetes/login", 200, login("hvs.k8s", 3600, true))
                .on("GET", "/v1/secret/data/app", 200,
                        "{\"data\":{\"data\":{\"password\":\"hunter2\"}}}");
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultSecretProvider provider = provider(vault, "secret/data/app",
                     login(vault, VaultLogin.Method.KUBERNETES, null, "app", fixed(JWT),
                             Clock.systemUTC()), Clock.systemUTC())) {

            assertEquals("hunter2", read(provider));

            FakeVaultServer.Request login = vault.requests().get(0);
            assertTrue(login.is("POST", "/v1/auth/kubernetes/login"), login.toString());
            assertEquals("{\"role\":\"app\",\"jwt\":\"" + JWT + "\"}", login.body());
            assertEquals("application/json", login.header("Content-Type"));
            assertNull(login.header("X-Vault-Token"), "a login is made without a token");

            FakeVaultServer.Request read = vault.requests().get(1);
            assertTrue(read.is("GET", "/v1/secret/data/app"), read.toString());
            assertEquals("hvs.k8s", read.header("X-Vault-Token"));
        }
    }

    @Test
    void anAppRoleLoginSendsTheRoleIdAndTheSecretIdToItsMount() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/ci-approle/login", 200, login("hvs.ar", 600, false));
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = login(vault, VaultLogin.Method.APPROLE, "/ci-approle/",
                     "8d4b5e2c-role", fixed("6a1f-secret-id"), Clock.systemUTC())) {

            assertEquals("hvs.ar", read(login));
            assertEquals("{\"role_id\":\"8d4b5e2c-role\",\"secret_id\":\"6a1f-secret-id\"}",
                    vault.requests().get(0).body());
            assertEquals("ci-approle", login.mount());
        }
    }

    @Test
    void aJwtLoginWithoutARoleLeavesItToTheMountsDefault() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/jwt/login", 200, login("hvs.jwt", 600, true));
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = login(vault, VaultLogin.Method.JWT, null, null, fixed(JWT),
                     Clock.systemUTC())) {

            assertEquals("hvs.jwt", read(login));
            assertEquals("{\"jwt\":\"" + JWT + "\"}", vault.requests().get(0).body());
        }
    }

    @Test
    void theNamespaceGoesWithTheLogin() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/jwt/login", 200, login("hvs.ns", 600, true));
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = new VaultLogin(vault.address(), VaultLogin.Method.JWT, null,
                     "app", fixed(JWT), "team-a", false, 10_000)) {

            read(login);
            assertEquals("team-a", vault.requests().get(0).header("X-Vault-Namespace"));
        }
    }

    /** Neither a JWT nor a secret id has quotes or line breaks; one that does is not passed on as JSON. */
    @Test
    void whatCannotBeInAJsonStringIsEscapedOrRefused() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/approle/login", 200, login("hvs.esc", 600, false));
        try (FakeVaultServer vault = new FakeVaultServer(context, script)) {
            try (VaultLogin login = login(vault, VaultLogin.Method.APPROLE, null, "role",
                    fixed("a\"b\\c"), Clock.systemUTC())) {
                read(login);
                assertEquals("{\"role_id\":\"role\",\"secret_id\":\"a\\\"b\\\\c\"}",
                        vault.requests().get(0).body());
            }
            try (VaultLogin login = login(vault, VaultLogin.Method.APPROLE, null, "role",
                    fixed("abc\ndef"), Clock.systemUTC())) {
                SecretUnavailableException refused = assertThrows(
                        SecretUnavailableException.class, () -> read(login));
                assertTrue(refused.getMessage().contains("control character at byte 3"),
                        refused.getMessage());
                assertFalse(refused.getMessage().contains("abc"), refused.getMessage());
            }
            assertEquals(1, vault.requests("POST", "/v1/auth/approle/login").size(),
                    "the refused one was sent");
        }
    }

    @Test
    void aRefusedLoginSaysWhereToLookAndQuotesNothing() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/kubernetes/login", 403,
                        "{\"errors\":[\"permission denied: echo hvs.leaked-in-error\"]}");
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = login(vault, VaultLogin.Method.KUBERNETES, null, "app",
                     fixed(JWT), Clock.systemUTC())) {

            SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                    () -> read(login));
            String message = refused.getMessage();
            assertTrue(message.contains("auth/kubernetes") && message.contains("403")
                    && message.contains("bound to this service account"), message);
            assertFalse(message.contains("hvs.leaked"), "the error body was quoted: " + message);
            assertFalse(message.contains(JWT), "the JWT was quoted: " + message);
        }
    }

    @Test
    void anAnswerWithoutATokenIsRefused() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/jwt/login", 200, "{\"auth\":null,\"warnings\":[]}");
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = login(vault, VaultLogin.Method.JWT, null, "app", fixed(JWT),
                     Clock.systemUTC())) {
            SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                    () -> read(login));
            assertTrue(refused.getMessage().contains("not in a shape"), refused.getMessage());
        }
    }

    // ---------------------------------------------------------- the token --

    @Test
    void oneLoginServesEveryRequestUntilTheTokenIsDue() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/jwt/login", 200, login("hvs.one", 3600, true));
        MovingClock clock = new MovingClock(START);
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = login(vault, VaultLogin.Method.JWT, null, "app", fixed(JWT),
                     clock)) {
            for (int i = 0; i < 10; i++) {
                assertEquals("hvs.one", read(login));
                clock.advance(Duration.ofMinutes(2));
            }
            assertEquals(1, vault.requests().size());
            assertEquals(START.plusSeconds(3600), login.credentialsValidUntil());
            assertEquals(1, login.generation());
        }
    }

    /**
     * Halfway through its TTL the token is renewed - the same token, longer;
     * when Vault grants less than half a TTL more (the role's max TTL is near)
     * a new login is made, with the JWT read again: the kubelet rotates it.
     */
    @Test
    void theTokenIsRenewedHalfwayAndALoginIsMadeAgainWhenItIsCapped() throws Exception {
        AtomicReference<String> jwt = new AtomicReference<>(JWT);
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/kubernetes/login", 200,
                        login("hvs.first", 600, true), login("hvs.second", 600, true))
                .on("POST", "/v1/auth/token/renew-self", 200,
                        login("hvs.first", 600, true), login("hvs.first", 100, true));
        MovingClock clock = new MovingClock(START);
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = login(vault, VaultLogin.Method.KUBERNETES, null, "app",
                     fixed(jwt), clock)) {

            assertEquals("hvs.first", read(login));
            clock.advance(Duration.ofMinutes(6));
            assertEquals("hvs.first", read(login), "renewed: the same token");
            FakeVaultServer.Request renewal = vault.requests().get(1);
            assertTrue(renewal.is("POST", "/v1/auth/token/renew-self"), renewal.toString());
            assertEquals("hvs.first", renewal.header("X-Vault-Token"));
            assertEquals("{\"increment\":600}", renewal.body());
            assertEquals(START.plus(Duration.ofMinutes(6)).plusSeconds(600),
                    login.credentialsValidUntil());
            assertEquals(1, login.generation());

            jwt.set(JWT + "rotated");
            clock.advance(Duration.ofMinutes(6));
            assertEquals("hvs.second", read(login), "capped: a new login");
            assertEquals(2, login.generation());
            List<FakeVaultServer.Request> logins =
                    vault.requests("POST", "/v1/auth/kubernetes/login");
            assertEquals(2, logins.size());
            assertTrue(logins.get(1).body().contains(JWT + "rotated"),
                    "the second login did not read the JWT again");
            assertEquals(START.plus(Duration.ofMinutes(6)).plusSeconds(600),
                    login.validUntil(1), "the replaced token's end is remembered");
        }
    }

    @Test
    void aTokenVaultWillNotRenewIsReplacedByALogin() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/approle/login", 200,
                        login("hvs.a", 600, false), login("hvs.b", 600, false));
        MovingClock clock = new MovingClock(START);
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = login(vault, VaultLogin.Method.APPROLE, null, "role",
                     fixed("sid"), clock)) {
            assertEquals("hvs.a", read(login));
            clock.advance(Duration.ofMinutes(6));
            assertEquals("hvs.b", read(login));
            assertTrue(vault.requests("POST", "/v1/auth/token/renew-self").isEmpty(),
                    "renewal asked for although Vault said renewable=false");
        }
    }

    @Test
    void aTokenWithoutATtlIsNeverDue() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/jwt/login", 200, login("hvs.forever", 0, false));
        MovingClock clock = new MovingClock(START);
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultLogin login = login(vault, VaultLogin.Method.JWT, null, "app", fixed(JWT),
                     clock)) {
            read(login);
            clock.advance(Duration.ofDays(400));
            read(login);
            assertEquals(1, vault.requests().size());
            assertNull(login.credentialsValidUntil());
        }
    }

    @Test
    void closingRevokesTheLeaseFirstAndThenTheToken() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/kubernetes/login", 200, login("hvs.k", 3600, true))
                .on("GET", "/v1/database/creds/app", 200, creds("v-app-1", "pw-one", 3600))
                .on("PUT", "/v1/sys/leases/revoke", 204, "")
                .on("POST", "/v1/auth/token/revoke-self", 204, "");
        try (FakeVaultServer vault = new FakeVaultServer(context, script)) {
            VaultLogin login = login(vault, VaultLogin.Method.KUBERNETES, null, "app",
                    fixed(JWT), Clock.systemUTC());
            VaultSecretProvider provider = provider(vault, "database/creds/app", login,
                    Clock.systemUTC());
            assertEquals("pw-one", read(provider));
            provider.close();

            List<FakeVaultServer.Request> requests = vault.requests();
            assertEquals(4, requests.size(), requests.toString());
            assertTrue(requests.get(2).is("PUT", "/v1/sys/leases/revoke"));
            assertEquals("hvs.k", requests.get(2).header("X-Vault-Token"));
            assertTrue(requests.get(3).is("POST", "/v1/auth/token/revoke-self"));
            assertEquals("hvs.k", requests.get(3).header("X-Vault-Token"));
            assertThrows(SecretUnavailableException.class, () -> read(login), "closed");
        }
    }

    // ---------------------------------------- the token bounds the lease --

    /**
     * Vault revokes a lease with the token that created it. A one-hour
     * database credential fetched with a ten-minute token is good for ten
     * minutes, and that is what the pool has to be told.
     */
    @Test
    void theTokensEndIsTheCredentialsEndWhenItComesFirst() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/jwt/login", 200, login("hvs.short", 600, true))
                .on("GET", "/v1/database/creds/app", 200, creds("v-app-1", "pw-one", 3600));
        MovingClock clock = new MovingClock(START);
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultSecretProvider provider = provider(vault, "database/creds/app",
                     login(vault, VaultLogin.Method.JWT, null, "app", fixed(JWT), clock),
                     clock)) {
            assertEquals("pw-one", read(provider));
            assertEquals(START.plusSeconds(600), provider.credentialsValidUntil());
        }
    }

    /**
     * The token is renewed when the lease is: both halfway through the
     * shorter of the two, and the credential stays the same user.
     */
    @Test
    void aRenewedTokenKeepsTheCredentialAlive() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/jwt/login", 200, login("hvs.t", 600, true))
                .on("POST", "/v1/auth/token/renew-self", 200, login("hvs.t", 600, true))
                .on("GET", "/v1/database/creds/app", 200, creds("v-app-1", "pw-one", 3600))
                .on("PUT", "/v1/sys/leases/renew", 200,
                        "{\"lease_id\":\"database/creds/app/v-app-1\",\"renewable\":true,"
                                + "\"lease_duration\":3600}");
        MovingClock clock = new MovingClock(START);
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultSecretProvider provider = provider(vault, "database/creds/app",
                     login(vault, VaultLogin.Method.JWT, null, "app", fixed(JWT), clock),
                     clock)) {
            assertEquals("v-app-1", provider.currentUser());
            assertEquals("pw-one", read(provider));

            clock.advance(Duration.ofMinutes(6));           // past half of the token's ten
            assertEquals("v-app-1", provider.currentUser(), "the same user");
            assertEquals("pw-one", read(provider));
            assertEquals(1, vault.requests("POST", "/v1/auth/token/renew-self").size());
            assertEquals(1, vault.requests("PUT", "/v1/sys/leases/renew").size());
            assertEquals(1, vault.requests("GET", "/v1/database/creds/app").size());
            assertEquals(START.plus(Duration.ofMinutes(6)).plusSeconds(600),
                    provider.credentialsValidUntil());
        }
    }

    /**
     * When the token cannot be renewed any further, a new login is made - and
     * the credential of the old token is not renewed but fetched again under
     * the new one, since it will be revoked together with the old token.
     */
    @Test
    void aCredentialOfAReplacedTokenIsFetchedAgain() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/jwt/login", 200,
                        login("hvs.old", 600, false), login("hvs.new", 600, false))
                .on("GET", "/v1/database/creds/app", 200,
                        creds("v-app-1", "pw-one", 3600), creds("v-app-2", "pw-two", 3600));
        MovingClock clock = new MovingClock(START);
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultSecretProvider provider = provider(vault, "database/creds/app",
                     login(vault, VaultLogin.Method.JWT, null, "app", fixed(JWT), clock),
                     clock)) {
            assertEquals("v-app-1", provider.currentUser());
            assertEquals("pw-one", read(provider));

            clock.advance(Duration.ofMinutes(6));
            assertEquals("v-app-2", provider.currentUser(), "a new user under the new token");
            assertEquals("pw-two", read(provider));
            assertTrue(vault.requests("PUT", "/v1/sys/leases/renew").isEmpty(),
                    "the old token's lease was renewed instead of replaced");
            List<FakeVaultServer.Request> fetches =
                    vault.requests("GET", "/v1/database/creds/app");
            assertEquals("hvs.new", fetches.get(1).header("X-Vault-Token"));
            assertEquals(START.plus(Duration.ofMinutes(6)).plusSeconds(600),
                    provider.credentialsValidUntil());
        }
    }

    /** A token revoked from outside: one new login, and the read goes through. */
    @Test
    void aRefusedTokenIsReplacedOnce() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/jwt/login", 200,
                        login("hvs.revoked", 3600, true), login("hvs.fresh", 3600, true));
        FakeVaultServer.Handler handler = request -> {
            if (request.is("GET", "/v1/secret/data/app")) {
                return "hvs.fresh".equals(request.header("X-Vault-Token"))
                        ? new FakeVaultServer.Answer(200,
                                "{\"data\":{\"data\":{\"password\":\"hunter2\"}}}")
                        : new FakeVaultServer.Answer(403,
                                "{\"errors\":[\"permission denied\"]}");
            }
            return script.answer(request);
        };
        try (FakeVaultServer vault = new FakeVaultServer(context, handler);
             VaultSecretProvider provider = provider(vault, "secret/data/app",
                     login(vault, VaultLogin.Method.JWT, null, "app", fixed(JWT),
                             Clock.systemUTC()), Clock.systemUTC())) {
            assertEquals("hunter2", read(provider));
            assertEquals(2, vault.requests("POST", "/v1/auth/jwt/login").size());
        }
    }

    /** A path the token may really not read: one new login, not a loop. */
    @Test
    void aPathTheTokenMayNotReadFailsAfterOneNewLogin() throws Exception {
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/jwt/login", 200, login("hvs.x", 3600, true))
                .on("GET", "/v1/secret/data/other", 403, "{\"errors\":[\"permission denied\"]}");
        try (FakeVaultServer vault = new FakeVaultServer(context, script);
             VaultSecretProvider provider = provider(vault, "secret/data/other",
                     login(vault, VaultLogin.Method.JWT, null, "app", fixed(JWT),
                             Clock.systemUTC()), Clock.systemUTC())) {
            SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                    () -> read(provider));
            assertTrue(refused.getMessage().contains("403"), refused.getMessage());
            assertEquals(2, vault.requests("POST", "/v1/auth/jwt/login").size());
            assertEquals(2, vault.requests("GET", "/v1/secret/data/other").size());
        }
    }

    // ------------------------------------------------------- configuration --

    private static Map<String, String> vaultSettings(String... pairs) {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "vault");
        settings.put("address", "https://127.0.0.1:8200");
        settings.put("path", "database/creds/app");
        if (pairs.length % 2 != 0) {
            throw new IllegalArgumentException("settings come in pairs: " + pairs.length);
        }
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            settings.put(pairs[i], pairs[i + 1]);
        }
        return settings;
    }

    @Test
    void theRegistryBuildsEachMethod(@TempDir Path directory) throws Exception {
        Path jwt = Files.writeString(directory.resolve("jwt"), JWT);
        Path secretId = Files.writeString(directory.resolve("secret-id"), "sid\n");
        FakeVaultServer.Script script = new FakeVaultServer.Script()
                .on("POST", "/v1/auth/jwt/login", 200, login("hvs.j", 600, true))
                .on("POST", "/v1/auth/approle/login", 200, login("hvs.a", 600, true))
                .on("POST", "/v1/auth/k8s-prod/login", 200, login("hvs.k", 600, true))
                .on("GET", "/v1/secret/data/app", 200,
                        "{\"data\":{\"data\":{\"password\":\"hunter2\"}}}");
        try (FakeVaultServer vault = new FakeVaultServer(context, script)) {
            String uri = "vault?address=" + vault.address() + "&path=secret/data/app"
                    + "&verify=false";
            try (SecretProvider provider = SecretProviders.fromUri(uri + "&auth-method=jwt"
                    + "&auth-role=app&jwt-provider=file&jwt-path=" + jwt)) {
                assertEquals("hunter2", read(provider));
            }
            try (SecretProvider provider = SecretProviders.fromUri(uri
                    + "&authMethod=approle&authRoleId=r-1&secret-id-provider=file"
                    + "&secret-id-path=" + secretId)) {
                assertEquals("hunter2", read(provider));
            }
            try (SecretProvider provider = SecretProviders.fromUri(uri
                    + "&auth-method=kubernetes&auth-mount=k8s-prod&auth-role=app"
                    + "&jwt-provider=file&jwt-path=" + jwt)) {
                assertEquals("hunter2", read(provider));
            }
            assertEquals("{\"role\":\"app\",\"jwt\":\"" + JWT + "\"}",
                    vault.requests("POST", "/v1/auth/jwt/login").get(0).body());
            assertEquals("{\"role_id\":\"r-1\",\"secret_id\":\"sid\"}",
                    vault.requests("POST", "/v1/auth/approle/login").get(0).body(),
                    "the secret id file's line break was not dropped");
            assertEquals(1, vault.requests("POST", "/v1/auth/k8s-prod/login").size());
        }
    }

    @Test
    void kubernetesReadsThePodsTokenUnlessToldOtherwise() {
        try (SecretProvider provider = SecretProviders.of(vaultSettings(
                "auth-method", "kubernetes", "auth-role", "app"))) {
            VaultLogin login = tokenOf(provider);
            assertEquals(VaultLogin.Method.KUBERNETES, login.method());
            assertEquals("kubernetes", login.mount());
            // Not run here: there is no pod. That the default is that file is the
            // registry's to say, and the message on a missing file names it.
            SecretUnavailableException missing = assertThrows(SecretUnavailableException.class,
                    () -> read(login));
            assertTrue(missing.getMessage().contains("serviceaccount/token"),
                    missing.getMessage());
        }
    }

    private static VaultLogin tokenOf(SecretProvider provider) {
        try {
            java.lang.reflect.Field token = VaultSecretProvider.class.getDeclaredField("token");
            token.setAccessible(true);
            return assertInstanceOf(VaultLogin.class, token.get(provider));
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    @Test
    void misconfigurationsAreRefusedAtTheStart() {
        IllegalArgumentException both = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(vaultSettings("auth-method", "jwt", "auth-role", "app",
                        "jwt-provider", "file", "jwt-path", "/x",
                        "token-provider", "file", "token-path", "/y")));
        assertTrue(both.getMessage().contains("token- settings"), both.getMessage());

        IllegalArgumentException noRole = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(vaultSettings("auth-method", "kubernetes")));
        assertTrue(noRole.getMessage().contains("auth-role"), noRole.getMessage());

        IllegalArgumentException noSecretId = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(vaultSettings("auth-method", "approle",
                        "auth-role-id", "r")));
        assertTrue(noSecretId.getMessage().contains("secret-id-provider"),
                noSecretId.getMessage());

        IllegalArgumentException noRoleId = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(vaultSettings("auth-method", "approle",
                        "secret-id-provider", "file", "secret-id-path", "/s")));
        assertTrue(noRoleId.getMessage().contains("auth-role-id"), noRoleId.getMessage());

        IllegalArgumentException noJwt = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(vaultSettings("auth-method", "jwt")));
        assertTrue(noJwt.getMessage().contains("jwt-provider"), noJwt.getMessage());

        IllegalArgumentException unknown = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(vaultSettings("auth-method", "userpass")));
        assertTrue(unknown.getMessage().contains("kubernetes, jwt, approle, aws, gcp and azure"),
                unknown.getMessage());

        IllegalArgumentException plain = assertThrows(IllegalArgumentException.class,
                () -> new VaultLogin("http://vault:8200", VaultLogin.Method.JWT, null, null,
                        fixed(JWT), null, true, 1000));
        assertTrue(plain.getMessage().contains("https only"), plain.getMessage());

        IllegalArgumentException badMount = assertThrows(IllegalArgumentException.class,
                () -> new VaultLogin("https://vault:8200", VaultLogin.Method.JWT, "../sys",
                        null, fixed(JWT), null, true, 1000));
        assertTrue(badMount.getMessage().contains("auth mount"), badMount.getMessage());

        IllegalArgumentException badRole = assertThrows(IllegalArgumentException.class,
                () -> new VaultLogin("https://vault:8200", VaultLogin.Method.JWT, null,
                        "app\r\nX: y", fixed(JWT), null, true, 1000));
        assertTrue(badRole.getMessage().contains("printable ASCII"), badRole.getMessage());
    }

    @Test
    void theDefaultIsStillATokenFromAProvider() {
        try (SecretProvider provider = SecretProviders.of(vaultSettings(
                "token-provider", "file", "token-path", "/run/secrets/vault-token"))) {
            java.lang.reflect.Field token;
            try {
                token = VaultSecretProvider.class.getDeclaredField("token");
                token.setAccessible(true);
                assertInstanceOf(FileSecretProvider.class, token.get(provider));
            } catch (ReflectiveOperationException e) {
                throw new AssertionError(e);
            }
        }
    }
}
