package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.crypto.OpenSslSigningKey;

/**
 * auth=jwt against an API that checks each bearer token with the public key,
 * as GitHub does for its apps: the token is signed by the client, reused while
 * it lasts, and signed afresh when the API answers 401.
 */
@Timeout(60)
class SelfSignedJwtTest {

    private static TestPki pki;
    private static Path keyFile;

    @BeforeAll
    static void key() throws Exception {
        Assumptions.assumeTrue(OpenSslSigningKey.available(), "no OpenSSL 3 here");
        pki = TestPki.generate();
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(pki.keystore)) {
            store.load(in, TestPki.STORE_PASSWORD.toCharArray());
        }
        Key key = store.getKey("server", TestPki.STORE_PASSWORD.toCharArray());
        keyFile = Files.createTempFile("app", ".pem");
        Files.writeString(keyFile, "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder(64,
                new byte[] {'\n'}).encodeToString(key.getEncoded()) + "\n-----END PRIVATE KEY-----\n");
    }

    @AfterAll
    static void cleanUp() throws IOException {
        if (keyFile != null) {
            Files.deleteIfExists(keyFile);
        }
    }

    /** What GitHub checks: RS256 by the app's key, iss the app id, a lifetime of at most ten minutes. */
    private static Predicate<String> github(Set<String> seen) {
        return header -> {
            try {
                String jwt = header.substring("Bearer ".length());
                String[] parts = jwt.split("\\.");
                Signature check = Signature.getInstance("SHA256withRSA");
                check.initVerify(pki.certificate.getPublicKey());
                check.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
                String claims = new String(Base64.getUrlDecoder().decode(parts[1]),
                        StandardCharsets.UTF_8);
                long now = System.currentTimeMillis() / 1000;
                long iat = Long.parseLong(claims.replaceAll(".*\"iat\":(\\d+).*", "$1"));
                long exp = Long.parseLong(claims.replaceAll(".*\"exp\":(\\d+).*", "$1"));
                boolean ok = check.verify(Base64.getUrlDecoder().decode(parts[2]))
                        && claims.contains("\"iss\":\"123456\"") && iat <= now && exp > now
                        && exp - iat <= 660;
                if (ok) {
                    seen.add(jwt);
                }
                return ok;
            } catch (Exception e) {
                return false;
            }
        };
    }

    private String url(FakeHttpsServer api) {
        return "https://localhost:" + api.port() + "?auth=jwt&tlsPin=" + pki.pin()
                + "&jwt-iss=123456&jwt-ttl=540&jwt-kid=app&provider=file&path="
                + keyFile.toString().replace('\\', '/');
    }

    @Test
    void signedHereReusedAndCheckedByTheApi() throws Exception {
        Set<String> tokens = ConcurrentHashMap.newKeySet();
        try (FakeHttpsServer api = new FakeHttpsServer(pki.serverContext());
             SeclumeHttp http = SeclumeHttp.of(url(api))) {
            api.accepts = github(tokens);
            for (int i = 0; i < 3; i++) {
                try (SeclumeHttp.Response response = http.send("GET", "/app/installations",
                        Map.of(), null)) {
                    assertEquals(200, response.status());
                }
            }
            assertEquals(1, tokens.size(), "one token for three calls");
            String header = new String(Base64.getUrlDecoder().decode(
                    tokens.iterator().next().split("\\.")[0]), StandardCharsets.UTF_8);
            assertEquals("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"app\"}", header);
        }
    }

    @Test
    void aRefusedTokenIsSignedAfreshOnce() throws Exception {
        Set<String> tokens = ConcurrentHashMap.newKeySet();
        AtomicInteger refusals = new AtomicInteger(1);
        try (FakeHttpsServer api = new FakeHttpsServer(pki.serverContext());
             SeclumeHttp http = SeclumeHttp.of(url(api))) {
            Predicate<String> check = github(tokens);
            api.accepts = value -> refusals.getAndDecrement() <= 0 && check.test(value);
            try (SeclumeHttp.Response response = http.send("POST", "/app/installations/1/"
                    + "access_tokens", Map.of(), new byte[0])) {
                assertEquals(200, response.status());
            }
            assertEquals(2, api.received.size(), "the 401, then the retry");
            assertTrue(api.received.get(1).authorized());
        }
    }

    @Test
    void settingsRefusals() {
        String base = "https://api.example?auth=jwt&provider=file&path=/x";
        assertThrows(IllegalArgumentException.class, () -> HttpSettings.of(base));
        assertThrows(IllegalArgumentException.class,
                () -> HttpSettings.of(base + "&jwt-iss=1&jwt-ttl=5"));
        assertThrows(IllegalArgumentException.class,
                () -> HttpSettings.of(base + "&jwt-iss=1&jwt-ttl=soon"));
    }
}
