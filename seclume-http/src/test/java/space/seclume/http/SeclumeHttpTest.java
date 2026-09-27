package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The client against a real TLS 1.3 server: every way of sending the
 * credential, every way a response body ends, connection reuse - and the
 * refusals that keep the credential where it belongs.
 */
@Timeout(60)
class SeclumeHttpTest {

    private static TestPki pki;
    private static Path tokenFile;

    @BeforeAll
    static void certificateAndSecret() throws Exception {
        pki = TestPki.generate();
        tokenFile = Files.createTempFile("http", ".token");
        Files.writeString(tokenFile, "ya29.test-token\n");        // the newline is dropped
    }

    @AfterAll
    static void cleanUp() throws IOException {
        Files.deleteIfExists(tokenFile);
    }

    private static String url(FakeHttpsServer server, String path, String extra) {
        return "https://localhost:" + server.port() + path + "?tlsPin=" + pki.pin() + extra
                + "&provider=file&path=" + tokenFile.toString().replace('\\', '/');
    }

    private static String text(SeclumeHttp.Response response) throws IOException {
        try (response) {
            return new String(response.body().readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void bearerByDefaultAndPathsResolvedAgainstTheBase() throws Exception {
        try (FakeHttpsServer server = new FakeHttpsServer(pki.serverContext());
             SeclumeHttp http = SeclumeHttp.of(url(server, "/v1/", ""))) {
            SeclumeHttp.Response response = http.send("GET", "/orders?status=open&page=2",
                    Map.of("Accept", List.of("text/plain")), null);
            assertEquals(200, response.status());
            assertEquals("text/plain", response.header("content-type"));
            assertEquals("GET /v1/orders?status=open&page=2", text(response));
            assertEquals("GET /v1/items", text(http.send("GET", "items", Map.of(), null)));
            assertEquals("POST /v1/orders {\"n\":1}", text(http.send("POST", "/orders",
                    Map.of("Content-Type", List.of("application/json")),
                    "{\"n\":1}".getBytes(StandardCharsets.UTF_8))));
            assertEquals("GET /v1/x", text(http.send("GET",
                    "https://localhost:" + server.port() + "/v1/x", Map.of(), null)));
            for (FakeHttpsServer.Received request : server.received) {
                assertTrue(request.authorized(), request.toString());
                assertEquals("seclume-http", request.headers().get("User-Agent").get(0));
                assertEquals("localhost:" + server.port(), request.headers().get("Host").get(0));
            }
            assertEquals("text/plain", server.received.get(0).headers().get("Accept").get(0));
            assertEquals(1, server.connections.get(), "one connection, kept alive");
        }
    }

    @Test
    void basicAndAHeaderOfTheApisOwn() throws Exception {
        try (FakeHttpsServer server = new FakeHttpsServer(pki.serverContext())) {
            server.expected = ("Basic " + Base64.getEncoder().encodeToString(
                    "deploy:ya29.test-token".getBytes(StandardCharsets.UTF_8)))
                    .getBytes(StandardCharsets.UTF_8);
            try (SeclumeHttp http = SeclumeHttp.of(url(server, "", "&auth=basic&user=deploy"))) {
                assertEquals(200, http.send("GET", "/", Map.of(), null).status());
            }
            server.headerName = "X-Api-Key";
            server.expected = "ya29.test-token".getBytes(StandardCharsets.UTF_8);
            try (SeclumeHttp http = SeclumeHttp.of(url(server, "", "&auth=header&header=X-Api-Key"))) {
                assertEquals(200, http.send("GET", "/", Map.of(), null).status());
            }
            server.headerName = "Authorization";
            server.expected = "ApiKey ya29.test-token".getBytes(StandardCharsets.UTF_8);
            try (SeclumeHttp http = SeclumeHttp.of(url(server, "",
                    "&auth=header&header=Authorization&prefix=ApiKey%20"))) {
                assertEquals(200, http.send("GET", "/", Map.of(), null).status());
            }
            assertTrue(server.received.stream().allMatch(FakeHttpsServer.Received::authorized));
        }
    }

    @Test
    void everyWayABodyEnds() throws Exception {
        try (FakeHttpsServer server = new FakeHttpsServer(pki.serverContext());
             SeclumeHttp http = SeclumeHttp.of(url(server, "", ""))) {
            assertEquals("hello world", text(http.send("GET", "/chunked", Map.of(), null)));
            assertEquals(200_000, http.send("GET", "/big", Map.of(), null).body()
                    .readAllBytes().length);
            SeclumeHttp.Response empty = http.send("DELETE", "/empty", Map.of(), null);
            assertEquals(204, empty.status());
            assertEquals(-1, empty.body().read());
            SeclumeHttp.Response head = http.send("HEAD", "/", Map.of(), null);
            assertEquals("6", head.header("Content-Length"));      // "HEAD /"
            assertEquals(-1, head.body().read());
            assertEquals("after", text(http.send("GET", "/continue", Map.of(), null)));
            assertEquals(1, server.connections.get(), "all on one kept connection");
            assertEquals("until the end", text(http.send("GET", "/close", Map.of(), null)));
            assertEquals("GET /", text(http.send("GET", "/", Map.of(), null)));
            assertEquals(2, server.connections.get(), "a new one after Connection: close");
        }
    }

    @Test
    void anUnreadBodyClosesItsConnection() throws Exception {
        try (FakeHttpsServer server = new FakeHttpsServer(pki.serverContext());
             SeclumeHttp http = SeclumeHttp.of(url(server, "", ""))) {
            SeclumeHttp.Response big = http.send("GET", "/big", Map.of(), null);
            big.body().readNBytes(10);
            big.close();
            assertEquals("GET /", text(http.send("GET", "/", Map.of(), null)));
            assertEquals(2, server.connections.get());
        }
    }

    @Test
    void aConnectionTheServerDroppedIsRetriedForIdempotentMethodsOnly() throws Exception {
        try (FakeHttpsServer server = new FakeHttpsServer(pki.serverContext());
             SeclumeHttp http = SeclumeHttp.of(url(server, "", ""))) {
            server.dropSilently = true;
            assertEquals("GET /a", text(http.send("GET", "/a", Map.of(), null)));
            Thread.sleep(200);
            assertEquals("GET /b", text(http.send("GET", "/b", Map.of(), null)));
            assertEquals(2, server.connections.get());
            Thread.sleep(200);
            assertThrows(IOException.class, () -> http.send("POST", "/c", Map.of(),
                    "once".getBytes(StandardCharsets.UTF_8)));
            assertFalse(server.received.stream().anyMatch(r -> r.target().equals("/c")),
                    "a POST is not sent twice");
        }
    }

    @Test
    void theCredentialStaysWithItsOrigin() throws Exception {
        try (FakeHttpsServer server = new FakeHttpsServer(pki.serverContext());
             SeclumeHttp http = SeclumeHttp.of(url(server, "", ""))) {
            IllegalArgumentException elsewhere = assertThrows(IllegalArgumentException.class,
                    () -> http.send("GET", "https://evil.example/steal", Map.of(), null));
            assertTrue(elsewhere.getMessage().contains("is not sent to https://evil.example"),
                    elsewhere.getMessage());
            assertThrows(IllegalArgumentException.class, () -> http.send("GET",
                    "https://localhost:" + (server.port() + 1) + "/", Map.of(), null));
            assertThrows(IllegalArgumentException.class,
                    () -> http.send("GET", "//evil.example/", Map.of(), null));

            SeclumeHttp.Response redirect = http.send("GET", "/redirect", Map.of(), null);
            assertEquals(302, redirect.status(), "not followed");
            assertEquals("https://elsewhere.example/", redirect.header("Location"));
            redirect.close();

            IllegalArgumentException own = assertThrows(IllegalArgumentException.class,
                    () -> http.send("GET", "/", Map.of("authorization", List.of("Bearer x")),
                            null));
            assertTrue(own.getMessage().contains("a value set by the application"),
                    own.getMessage());
            assertThrows(IllegalArgumentException.class, () -> http.send("GET", "/",
                    Map.of("X-Note", List.of("a\r\nAuthorization: Bearer x")), null));
            assertThrows(IllegalArgumentException.class,
                    () -> http.send("GET", "/", Map.of("Host", List.of("evil.example")), null));
            assertThrows(IllegalArgumentException.class,
                    () -> http.send("GET\r\n", "/", Map.of(), null));
            assertTrue(server.received.stream().noneMatch(r -> r.target().contains("steal")));
        }
    }

    @Test
    void aWrongSecretIsTheServersRefusalNotAnError() throws Exception {
        try (FakeHttpsServer server = new FakeHttpsServer(pki.serverContext());
             SeclumeHttp http = SeclumeHttp.of(url(server, "", ""))) {
            server.expected = "Bearer something-else".getBytes(StandardCharsets.UTF_8);
            SeclumeHttp.Response refused = http.send("GET", "/", Map.of(), null);
            assertEquals(401, refused.status());
            assertNull(refused.header("X-Absent"));
            refused.close();
        }
    }

    @Test
    void aSecretWithALineBreakIsNotSent() throws Exception {
        Path broken = Files.createTempFile("http", ".token");
        try (FakeHttpsServer server = new FakeHttpsServer(pki.serverContext());
             SeclumeHttp http = SeclumeHttp.of("https://localhost:" + server.port()
                     + "?tlsPin=" + pki.pin() + "&provider=file&path="
                     + broken.toString().replace('\\', '/'))) {
            Files.writeString(broken, "token\r\nX-Injected: 1");
            IOException e = assertThrows(IOException.class,
                    () -> http.send("GET", "/", Map.of(), null));
            assertTrue(e.getMessage().contains("line break"), e.getMessage());
            assertTrue(server.received.isEmpty());
        } finally {
            Files.deleteIfExists(broken);
        }
    }

    @Test
    void aServerWithTheWrongCertificateIsRefused() throws Exception {
        TestPki other = TestPki.generate();
        try (FakeHttpsServer server = new FakeHttpsServer(other.serverContext());
             SeclumeHttp http = SeclumeHttp.of(url(server, "", ""))) {
            assertThrows(IOException.class, () -> http.send("GET", "/", Map.of(), null));
            assertTrue(server.received.isEmpty());
        }
    }
}
