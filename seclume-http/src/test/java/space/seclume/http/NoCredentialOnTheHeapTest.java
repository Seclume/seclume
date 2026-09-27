package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.ref.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

import space.seclume.tck.NoSecretInHeap;

/**
 * The claim itself: after calling APIs every way this module knows - a bearer
 * token on its own, Basic through Spring's RestClient, an API key in a header
 * of its own through RestTemplate, each over kept connections, and OAuth 2.0
 * client credentials through RestClient - neither the token, the password, the
 * key, the client secret nor the access token it bought is on this JVM's heap,
 * and neither are the base64 forms the Basic credentials travelled in.
 *
 * <p>The servers run in a JVM of their own ({@link FakeHttpsServerMain}); this
 * JVM only ever holds the paths - to hand to the secret provider, and to the
 * heap search, which runs in a third process. Until the end, where the control
 * reads one secret into a {@code String} on purpose and the search has to
 * find it.
 */
@Timeout(300)
class NoCredentialOnTheHeapTest {

    @Test
    void noTokenPasswordOrKeyAndNoBasicOnTheHeap() throws Exception {
        TestPki pki = TestPki.generate();
        Path directory = Files.createTempDirectory("seclume-http-proof");
        Process server = new ProcessBuilder(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED",
                "-cp", System.getProperty("java.class.path"),
                FakeHttpsServerMain.class.getName(),
                pki.keystore.toString(), directory.toString()))
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
        try (BufferedReader out = new BufferedReader(new InputStreamReader(
                server.getInputStream(), StandardCharsets.UTF_8))) {
            String ready = out.readLine();
            assertTrue(ready != null && ready.startsWith("READY "), "the server said: " + ready);
            String[] ports = ready.split(" ");
            String trust = "?tlsPin=" + pki.pin() + "&provider=file&path=";

            try (SeclumeHttp bearer = SeclumeHttp.of("https://localhost:" + ports[1] + "/v1"
                    + trust + slashes(directory.resolve("token")))) {
                for (int i = 0; i < 3; i++) {
                    try (SeclumeHttp.Response response = bearer.send("GET", "/orders/" + i,
                            Map.of(), null)) {
                        assertEquals(200, response.status());
                        response.body().readAllBytes();
                    }
                }
            }
            try (SeclumeHttp basic = SeclumeHttp.of("https://localhost:" + ports[2]
                    + trust + slashes(directory.resolve("password")) + "&auth=basic&user=deploy")) {
                RestClient rest = RestClient.builder()
                        .requestFactory(new SeclumeHttpRequestFactory(basic))
                        .baseUrl("https://localhost:" + ports[2]).build();
                rest.post().uri("/deploy").body("{\"version\":\"1.2\"}").retrieve()
                        .body(String.class);
                rest.get().uri("/status").retrieve().body(String.class);
            }
            try (SeclumeHttp header = SeclumeHttp.of("https://localhost:" + ports[3]
                    + trust + slashes(directory.resolve("api-key"))
                    + "&auth=header&header=X-Api-Key")) {
                RestTemplate template = new RestTemplate(new SeclumeHttpRequestFactory(header));
                template.getForObject("https://localhost:" + ports[3] + "/search?q=x",
                        String.class);
            }

            try (SeclumeHttp oauth = SeclumeHttp.of("https://localhost:" + ports[5]
                    + "/graph?auth=oauth2&tlsPin=" + pki.pin() + "&token-url=https://localhost:"
                    + ports[4] + "/oauth2/token&token-tlsPin=" + pki.pin()
                    + "&client-id=app-1&scope=graph&provider=file&path="
                    + slashes(directory.resolve("client-secret")))) {
                RestClient rest = RestClient.builder()
                        .requestFactory(new SeclumeHttpRequestFactory(oauth))
                        .baseUrl("https://localhost:" + ports[5] + "/graph").build();
                rest.get().uri("/me").retrieve().body(String.class);
                rest.get().uri("/users").retrieve().body(String.class);
            }

            server.getOutputStream().close();
            assertTrue(server.waitFor(30, TimeUnit.SECONDS));
            List<String> tail = new ArrayList<>();
            for (String line; (line = out.readLine()) != null; ) {
                if (line.startsWith("RECEIVED")) {
                    tail.add(line);
                }
            }
            assertEquals(List.of("RECEIVED 8 AUTHORIZED 8 TOKENS 1"), tail);

            for (String secret : List.of("token", "password", "api-key", "basic.b64",
                    "client-secret", "access-token", "oauth-basic.b64")) {
                NoSecretInHeap.assertAbsent(directory.resolve(secret));
            }

            // The control: a search that cannot fail proves nothing. The token as
            // the String an interceptor would hold it in - and now it has to be found.
            String leaked = Files.readString(directory.resolve("token")); // seclume-allow: the control, put on the heap on purpose
            AssertionError found = assertThrows(AssertionError.class,
                    () -> NoSecretInHeap.assertAbsent(directory.resolve("token")));
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
