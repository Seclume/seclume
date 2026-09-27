package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.web.client.RestClient;

/**
 * auth=oauth2 against a token endpoint and an API, both real TLS 1.3 servers:
 * the grant with the secret in Basic and in the form, the token kept and
 * reused, renewed when it runs out and when the API answers 401, and the
 * token endpoint's refusal passed on with its reason.
 */
@Timeout(60)
class OAuthClientCredentialsTest {

    private static TestPki pki;
    private static Path secretFile;

    @BeforeAll
    static void certificateAndSecret() throws Exception {
        pki = TestPki.generate();
        secretFile = Files.createTempFile("oauth", ".secret");
        Files.writeString(secretFile, "s3cr:t/+&=ü");
    }

    @AfterAll
    static void cleanUp() throws IOException {
        Files.deleteIfExists(secretFile);
    }

    private static String url(FakeHttpsServer api, FakeTokenServer tokens, String extra) {
        return "https://localhost:" + api.port() + "/v1?auth=oauth2&tlsPin=" + pki.pin()
                + "&token-url=https://localhost:" + tokens.port() + "/tenant/oauth2/v2.0/token"
                + "&token-tlsPin=" + pki.pin() + "&client-id=app-1" + extra
                + "&provider=file&path=" + secretFile.toString().replace('\\', '/');
    }

    private static FakeHttpsServer api(FakeTokenServer tokens) throws Exception {
        FakeHttpsServer api = new FakeHttpsServer(pki.serverContext());
        api.accepts = tokens.valid::contains;
        return api;
    }

    private static String text(SeclumeHttp.Response response) throws IOException {
        try (response) {
            return new String(response.body().readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void basicClientAuthAndTheTokenIsReused() throws Exception {
        try (FakeTokenServer tokens = new FakeTokenServer(pki.serverContext());
             FakeHttpsServer api = api(tokens);
             SeclumeHttp http = SeclumeHttp.of(url(api, tokens,
                     "&scope=https%3A%2F%2Fgraph.example%2F.default"))) {
            for (int i = 0; i < 3; i++) {
                assertEquals("GET /v1/me", text(http.send("GET", "/me", Map.of(), null)));
            }
            assertEquals(1, tokens.issued.get(), "one token for three calls");
            assertEquals(List.of("basic"), tokens.clientAuths);
            assertEquals("https://graph.example/.default", tokens.grants.get(0).get("scope"));
            assertEquals("app-1", tokens.grants.get(0).get("client_id"));
            assertTrue(api.received.stream().allMatch(FakeHttpsServer.Received::authorized));
        }
    }

    @Test
    void postClientAuthWithResourceAndAudience() throws Exception {
        try (FakeTokenServer tokens = new FakeTokenServer(pki.serverContext());
             FakeHttpsServer api = api(tokens);
             SeclumeHttp http = SeclumeHttp.of(url(api, tokens,
                     "&client-auth=post&resource=api%3A%2F%2Forders&audience=orders"))) {
            assertEquals(200, http.send("GET", "/", Map.of(), null).status());
            assertEquals(List.of("post"), tokens.clientAuths);
            assertEquals("api://orders", tokens.grants.get(0).get("resource"));
            assertEquals("orders", tokens.grants.get(0).get("audience"));
        }
    }

    @Test
    void anExpiredTokenIsRenewedAndAStringLifetimeIsRead() throws Exception {
        try (FakeTokenServer tokens = new FakeTokenServer(pki.serverContext());
             FakeHttpsServer api = api(tokens);
             SeclumeHttp http = SeclumeHttp.of(url(api, tokens, ""))) {
            tokens.expiresIn = "\"1\"";
            tokens.chunked = true;
            assertEquals(200, http.send("GET", "/a", Map.of(), null).status());
            Thread.sleep(1_300);
            assertEquals(200, http.send("GET", "/b", Map.of(), null).status());
            assertEquals(2, tokens.issued.get());
        }
    }

    @Test
    void aRevokedTokenIsReplacedOnce() throws Exception {
        try (FakeTokenServer tokens = new FakeTokenServer(pki.serverContext());
             FakeHttpsServer api = api(tokens);
             SeclumeHttp http = SeclumeHttp.of(url(api, tokens, ""))) {
            assertEquals(200, http.send("GET", "/a", Map.of(), null).status());
            tokens.valid.clear();                                   // revoked
            assertEquals("POST /v1/orders once", text(http.send("POST", "/orders", Map.of(),
                    "once".getBytes(StandardCharsets.UTF_8))));
            assertEquals(2, tokens.issued.get());

            api.accepts = value -> false;                           // nothing will do
            SeclumeHttp.Response refused = http.send("GET", "/c", Map.of(), null);
            assertEquals(401, refused.status(), "one renewal, then the answer as it is");
            refused.close();
            assertEquals(3, tokens.issued.get());
        }
    }

    @Test
    void theTokenEndpointsRefusalIsPassedOn() throws Exception {
        try (FakeTokenServer tokens = new FakeTokenServer(pki.serverContext());
             FakeHttpsServer api = api(tokens);
             SeclumeHttp http = SeclumeHttp.of(url(api, tokens, ""))) {
            tokens.clientSecret = "something else";
            IOException refused = assertThrows(IOException.class,
                    () -> http.send("GET", "/", Map.of(), null));
            assertTrue(refused.getMessage().contains("invalid_client"), refused.getMessage());
            assertTrue(refused.getMessage().contains("AADSTS7000215"), refused.getMessage());
            assertTrue(api.received.isEmpty(), "nothing reached the API");
        }
    }

    @Test
    void onlyBearerTokensAreSent() throws Exception {
        try (FakeTokenServer tokens = new FakeTokenServer(pki.serverContext());
             FakeHttpsServer api = api(tokens);
             SeclumeHttp http = SeclumeHttp.of(url(api, tokens, ""))) {
            tokens.tokenType = "mac";
            IOException e = assertThrows(IOException.class,
                    () -> http.send("GET", "/", Map.of(), null));
            assertTrue(e.getMessage().contains("only Bearer"), e.getMessage());
        }
    }

    @Test
    void throughSpringsRestClient() throws Exception {
        try (FakeTokenServer tokens = new FakeTokenServer(pki.serverContext());
             FakeHttpsServer api = api(tokens);
             SeclumeHttp http = SeclumeHttp.of(url(api, tokens, ""))) {
            RestClient rest = RestClient.builder()
                    .requestFactory(new SeclumeHttpRequestFactory(http))
                    .baseUrl("https://localhost:" + api.port() + "/v1").build();
            assertEquals("GET /v1/users/7", rest.get().uri("/users/{id}", 7).retrieve()
                    .body(String.class));
        }
    }

    @Test
    void privateKeyJwtWithoutAnySecret() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(
                space.seclume.crypto.OpenSslSigningKey.available(), "no OpenSSL 3 here");
        java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
        try (java.io.InputStream in = Files.newInputStream(pki.keystore)) {
            store.load(in, TestPki.STORE_PASSWORD.toCharArray());
        }
        java.security.Key key = store.getKey("server", TestPki.STORE_PASSWORD.toCharArray());
        Path keyFile = Files.createTempFile("oauth", ".pem");
        Path certFile = Files.createTempFile("oauth", ".crt");
        try (FakeTokenServer tokens = new FakeTokenServer(pki.serverContext());
             FakeHttpsServer api = api(tokens)) {
            java.util.Base64.Encoder mime = java.util.Base64.getMimeEncoder(64, new byte[] {'\n'});
            Files.writeString(keyFile, "-----BEGIN PRIVATE KEY-----\n"
                    + mime.encodeToString(key.getEncoded()) + "\n-----END PRIVATE KEY-----\n");
            Files.writeString(certFile, "-----BEGIN CERTIFICATE-----\n"
                    + mime.encodeToString(pki.certificate.getEncoded())
                    + "\n-----END CERTIFICATE-----\n");
            String tokenUrl = "https://localhost:" + tokens.port() + "/tenant/oauth2/v2.0/token";
            tokens.assertionKey = pki.certificate.getPublicKey();
            tokens.audience = tokenUrl;
            try (SeclumeHttp http = SeclumeHttp.of("https://localhost:" + api.port()
                    + "/v1?auth=oauth2&tlsPin=" + pki.pin() + "&token-url=" + tokenUrl
                    + "&token-tlsPin=" + pki.pin() + "&client-id=app-1"
                    + "&client-auth=private_key_jwt&assertion-kid=k1&assertion-certificate="
                    + certFile.toString().replace('\\', '/')
                    + "&provider=file&path=" + keyFile.toString().replace('\\', '/'))) {
                assertEquals("GET /v1/me", text(http.send("GET", "/me", Map.of(), null)));
            }
            assertEquals(List.of("private_key_jwt"), tokens.clientAuths);
            String header = tokens.assertionHeaders.get(0);
            assertTrue(header.contains("\"alg\":\"RS256\"") && header.contains("\"kid\":\"k1\"")
                    && header.contains("\"x5t#S256\":\"") && !header.contains("\"x5t\":"),
                    header);
            assertTrue(api.received.stream().allMatch(FakeHttpsServer.Received::authorized));

            // a key the endpoint does not know is refused, with its reason
            tokens.assertionKey = java.security.KeyPairGenerator.getInstance("RSA")
                    .generateKeyPair().getPublic();
            try (SeclumeHttp http = SeclumeHttp.of("https://localhost:" + api.port()
                    + "/v1?auth=oauth2&tlsPin=" + pki.pin() + "&token-url=" + tokenUrl
                    + "&token-tlsPin=" + pki.pin() + "&client-id=app-1"
                    + "&client-auth=private_key_jwt"
                    + "&provider=file&path=" + keyFile.toString().replace('\\', '/'))) {
                IOException refused = assertThrows(IOException.class,
                        () -> http.send("GET", "/me", Map.of(), null));
                assertTrue(refused.getMessage().contains("invalid_client"), refused.getMessage());
            }
        } finally {
            Files.deleteIfExists(keyFile);
            Files.deleteIfExists(certFile);
        }
    }

    @Test
    void settingsRefusals() {
        String base = "https://api.example?auth=oauth2&provider=file&path=/x";
        assertThrows(IllegalArgumentException.class, () -> HttpSettings.of(base
                + "&client-id=a"));
        assertThrows(IllegalArgumentException.class, () -> HttpSettings.of(base
                + "&token-url=https://login.example/token"));
        IllegalArgumentException clear = assertThrows(IllegalArgumentException.class,
                () -> HttpSettings.of(base + "&client-id=a&token-url=http://login.example/t"));
        assertTrue(clear.getMessage().contains("https://"), clear.getMessage());
        assertThrows(IllegalArgumentException.class, () -> HttpSettings.of(base
                + "&client-id=a&token-url=https://login.example/t&client-auth=jwt"));
        assertThrows(IllegalArgumentException.class, () -> HttpSettings.of(base
                + "&client-id=a&token-url=https://login.example/t&assertion-kid=k"));
    }

    /**
     * A chunk size near 2^31: {@code at + size} wrapped in int and slipped
     * past the size check (audit, 27.09.2026). It has to be refused as too large.
     */
    @Test
    void aChunkSizeThatWouldOverflowIsRefused() throws Exception {
        try (FakeTokenServer tokens = new FakeTokenServer(pki.serverContext());
             FakeHttpsServer api = api(tokens);
             SeclumeHttp http = SeclumeHttp.of(url(api, tokens, ""))) {
            tokens.rawChunkedBody = "1\r\n{\r\n7fffffff\r\n\r\n0\r\n\r\n";
            Exception refused = org.junit.jupiter.api.Assertions.assertThrows(Exception.class,
                    () -> http.send("GET", "/", Map.of(), null));
            StringBuilder chain = new StringBuilder();
            for (Throwable t = refused; t != null; t = t.getCause()) {
                chain.append(t.getMessage()).append(" / ");
            }
            org.junit.jupiter.api.Assertions.assertTrue(chain.toString().contains("larger than"),
                    chain.toString());
        }
    }
}
