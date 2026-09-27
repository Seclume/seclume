package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.client.RestClient;
import org.springframework.web.service.annotation.GetExchange;

import space.seclume.http.SeclumeHttp;

/**
 * Two APIs from properties alone - each its own RestClient bean under its
 * name, each with its own secret sent only to its own server - and an
 * {@code @HttpExchange} interface made on one of them.
 */
@Timeout(60)
class HttpClientsAutoConfigurationTest {

    /** The typed client of the second API. */
    public interface SearchApi {
        @GetExchange("/docs/{id}")
        String doc(@PathVariable("id") String id);
    }

    private static TestPki pki;
    private static Path paymentsToken;
    private static Path searchKey;

    @BeforeAll
    static void certificateAndSecrets() throws Exception {
        pki = TestPki.generate();
        paymentsToken = Files.createTempFile("payments", ".token");
        Files.writeString(paymentsToken, "pay-token");
        searchKey = Files.createTempFile("search", ".key");
        Files.writeString(searchKey, "search-key");
    }

    @AfterAll
    static void cleanUp() throws IOException {
        Files.deleteIfExists(paymentsToken);
        Files.deleteIfExists(searchKey);
    }

    /** An HTTPS server that answers with what it saw: path and the credential header's verdict. */
    private static HttpsServer server(String header, String expected, List<String> seen)
            throws Exception {
        HttpsServer server = HttpsServer.create(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(pki.serverContext()));
        server.createContext("/", exchange -> {
            String given = exchange.getRequestHeaders().getFirst(header);
            boolean ok = expected.equals(given);
            String path = exchange.getRequestURI().toString();
            seen.add(path + (ok ? " ok" : " refused"));
            byte[] body = (ok ? "hello " + path : "no").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/plain");
            exchange.sendResponseHeaders(ok ? 200 : 401, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        return server;
    }

    private static AnnotationConfigApplicationContext context(Map<String, Object> properties) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test", properties));
        context.register(SeclumeHttpClientsAutoConfiguration.class);
        context.refresh();
        return context;
    }

    private static String url(HttpsServer server, String path, String extra, Path secret) {
        return "https://localhost:" + server.getAddress().getPort() + path + "?tlsPin="
                + pki.pin() + extra + "&provider=file&path="
                + secret.toString().replace('\\', '/');
    }

    @Test
    void twoApisTwoSecretsEachToItsOwnServer() throws Exception {
        List<String> paymentsSeen = new CopyOnWriteArrayList<>();
        List<String> searchSeen = new CopyOnWriteArrayList<>();
        HttpsServer payments = server("Authorization", "Bearer pay-token", paymentsSeen);
        HttpsServer search = server("Authorization", "ApiKey search-key", searchSeen);
        try {
            Map<String, Object> properties = new LinkedHashMap<>();
            properties.put("seclume.http.clients.payments.url",
                    url(payments, "/v2", "", paymentsToken));
            properties.put("seclume.http.clients.search.url", url(search, "", 
                    "&auth=header&header=Authorization&prefix=ApiKey%20", searchKey));
            properties.put("seclume.http.clients.search.interface", SearchApi.class.getName());
            try (AnnotationConfigApplicationContext context = context(properties)) {
                RestClient paymentsClient = context.getBean("payments", RestClient.class);
                assertEquals("hello /v2/charges/7", paymentsClient.get()
                        .uri("/charges/{id}", 7).retrieve().body(String.class));

                assertEquals("hello /docs/abc", context.getBean(SearchApi.class).doc("abc"));
                assertEquals(2, context.getBeansOfType(RestClient.class).size());
                assertEquals(2, context.getBeansOfType(SeclumeHttp.class).size());

                // the payments client does not carry its token to the search server
                String elsewhere = "https://localhost:" + search.getAddress().getPort() + "/x";
                assertThrows(IllegalArgumentException.class, () -> paymentsClient.get()
                        .uri(elsewhere).retrieve().body(String.class));
            }
            assertEquals(List.of("/v2/charges/7 ok"), paymentsSeen);
            assertEquals(List.of("/docs/abc ok"), searchSeen);
        } finally {
            payments.stop(0);
            search.stop(0);
        }
    }

    @Test
    void withoutClientsNothingIsMade() {
        try (AnnotationConfigApplicationContext context = context(Map.of())) {
            assertTrue(context.getBeansOfType(RestClient.class).isEmpty());
        }
    }

    @Test
    void mistakesAreNamed() {
        Exception missing = assertThrows(Exception.class, () -> context(
                Map.of("seclume.http.clients.broken.interface", SearchApi.class.getName())));
        assertTrue(String.valueOf(rootMessage(missing)).contains("broken.url is missing"),
                rootMessage(missing));
        Exception notAnInterface = assertThrows(Exception.class, () -> context(Map.of(
                "seclume.http.clients.x.url", "https://localhost:1?provider=file&path=/x",
                "seclume.http.clients.x.interface", String.class.getName())));
        assertTrue(rootMessage(notAnInterface).contains("not an interface"),
                rootMessage(notAnInterface));
        BeanCreationException http = assertThrows(BeanCreationException.class, () -> context(
                Map.of("seclume.http.clients.y.url", "http://localhost:1?provider=file&path=/x"))
                .getBean("y"));
        assertTrue(rootMessage(http).contains("https://"), rootMessage(http));
    }

    private static String rootMessage(Throwable e) {
        Throwable cause = e;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return String.valueOf(cause.getMessage());
    }
}
