package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

/**
 * Spring's RestClient and RestTemplate on the request factory: the credential
 * is added below them, so no interceptor, default header or
 * {@code setBearerAuth} is involved - and one that tries is refused.
 */
@Timeout(60)
class SpringRestClientTest {

    private static TestPki pki;
    private static Path tokenFile;

    @BeforeAll
    static void certificateAndSecret() throws Exception {
        pki = TestPki.generate();
        tokenFile = Files.createTempFile("http", ".token");
        Files.writeString(tokenFile, "ya29.test-token");
    }

    @AfterAll
    static void cleanUp() throws IOException {
        Files.deleteIfExists(tokenFile);
    }

    private static SeclumeHttp api(FakeHttpsServer server) {
        return SeclumeHttp.of("https://localhost:" + server.port() + "/v1?tlsPin=" + pki.pin()
                + "&provider=file&path=" + tokenFile.toString().replace('\\', '/'));
    }

    @Test
    void restClientGetsAndPosts() throws Exception {
        try (FakeHttpsServer server = new FakeHttpsServer(pki.serverContext());
             SeclumeHttp api = api(server)) {
            RestClient rest = RestClient.builder()
                    .requestFactory(new SeclumeHttpRequestFactory(api))
                    .baseUrl("https://localhost:" + server.port() + "/v1")
                    .build();
            assertEquals("GET /v1/orders/42", rest.get().uri("/orders/{id}", 42)
                    .retrieve().body(String.class));
            assertEquals("POST /v1/orders {\"item\":\"book\"}", rest.post().uri("/orders")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"item\":\"book\"}")
                    .retrieve().body(String.class));
            assertEquals("hello world", rest.get().uri("/chunked").retrieve()
                    .body(String.class));
            HttpClientErrorException missing = assertThrows(HttpClientErrorException.class,
                    () -> rest.get().uri("/missing").retrieve().body(String.class));
            assertEquals(HttpStatus.NOT_FOUND, missing.getStatusCode());
            assertEquals("no orders", missing.getResponseBodyAsString());
            assertTrue(server.received.stream().allMatch(FakeHttpsServer.Received::authorized));
            assertEquals("application/json",
                    server.received.get(1).headers().get("Content-Type").get(0));
        }
    }

    @Test
    void restTemplateToo() throws Exception {
        try (FakeHttpsServer server = new FakeHttpsServer(pki.serverContext());
             SeclumeHttp api = api(server)) {
            RestTemplate template = new RestTemplate(new SeclumeHttpRequestFactory(api));
            assertEquals("GET /v1/items?page=2", template.getForObject(
                    "https://localhost:" + server.port() + "/v1/items?page=2", String.class));
        }
    }

    @Test
    void aTokenSetInSpringIsRefusedNotSent() throws Exception {
        try (FakeHttpsServer server = new FakeHttpsServer(pki.serverContext());
             SeclumeHttp api = api(server)) {
            RestClient rest = RestClient.builder()
                    .requestFactory(new SeclumeHttpRequestFactory(api))
                    .defaultHeaders(h -> h.setBearerAuth("a-token-in-a-string"))
                    .build();
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> rest.get().uri("https://localhost:" + server.port() + "/v1/x")
                            .retrieve().body(String.class));
            assertTrue(refused.getMessage().contains("Authorization"), refused.getMessage());
            RestClient elsewhere = RestClient.builder()
                    .requestFactory(new SeclumeHttpRequestFactory(api)).build();
            assertThrows(IllegalArgumentException.class, () -> elsewhere.get()
                    .uri("https://example.org/").retrieve().body(String.class));
            assertTrue(server.received.isEmpty());
        }
    }
}
