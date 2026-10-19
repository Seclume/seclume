package space.seclume.elasticsearch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.transport.rest5_client.low_level.Request;

import space.seclume.tck.NoSecretInHeap;

/**
 * The claim itself: after indexing and reading through the typed client, the
 * low-level clients of Elasticsearch 9 and 8 and the OpenSearch client, the
 * API key is nowhere on this JVM's heap. The server runs in a JVM of its own
 * ({@link SearchServerMain}) and made the key; this one only ever holds the
 * path.
 */
@Timeout(300)
class NoKeyOnTheHeapTest {

    @Test
    void theKeyIsNotOnTheHeap() throws Exception {
        TestPki pki = TestPki.generate();
        Path directory = Files.createTempDirectory("seclume-es-proof");
        Process server = new ProcessBuilder(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED",
                "-cp", System.getProperty("java.class.path"),
                SearchServerMain.class.getName(),
                pki.keystore.toString(), directory.toString()))
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
        try (BufferedReader out = new BufferedReader(new InputStreamReader(
                server.getInputStream(), StandardCharsets.UTF_8))) {
            String ready = out.readLine();
            assertTrue(ready != null && ready.startsWith("READY "), "the server said: " + ready);
            Path key = directory.resolve("es.key");
            String url = "https://localhost:" + ready.substring(6) + "/?auth=apikey"
                    + "&provider=file&path=" + key.toString().replace('\\', '/')
                    + "&tlsPin=" + pki.pin();

            ElasticsearchClient es = SeclumeElasticsearch.client(url);
            try {
                es.info();
                es.index(i -> i.index("orders").id("1").document(Map.of("sku", "a-1")));
            } finally {
                es.close();
            }
            try (var client = SeclumeElasticsearch.restClient(url)) {
                client.performRequest(new org.elasticsearch.client.Request("GET", "/"));
            }
            try (var client = SeclumeElasticsearch.rest5Client(url)) {
                client.performRequest(new Request("GET", "/"));
            }
            var os = SeclumeOpenSearch.transport(url);
            try {
                new org.opensearch.client.opensearch.OpenSearchClient(os).info();
            } finally {
                os.close();
            }

            server.getOutputStream().close();
            assertTrue(server.waitFor(30, TimeUnit.SECONDS));
            assertEquals("RECEIVED 5 AUTHORIZED 5", out.readLine());
            NoSecretInHeap.assertAbsent(key);
        } finally {
            server.destroyForcibly();
        }
    }
}
