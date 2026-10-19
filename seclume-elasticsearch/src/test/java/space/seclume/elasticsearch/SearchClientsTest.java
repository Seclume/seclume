package space.seclume.elasticsearch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.transport.rest5_client.low_level.Request;
import co.elastic.clients.transport.rest5_client.low_level.Rest5Client;

import space.seclume.http.SeclumeSslSocketFactory;

/**
 * The three clients against a local HTTPS server (the JDK's TLS 1.3) that
 * accepts only the real credential: the requests arrive authorized, so the
 * secret was written in - and a document holding a placeholder arrives with
 * the placeholder, so no body was touched.
 */
@Timeout(120)
class SearchClientsTest {

    private static final String KEY = "VnVhQ2ZHY0JDZGJrUW0tZTVhT3g6dWkybHAyYXhUTm1zeWFrdzl0dk5udw==";
    private static final String PASSWORD = "os-password-4f1b9c";

    @TempDir
    static Path dir;
    private static TestPki pki;
    private static FakeHttpsServer server;
    private static Path keyFile;
    private static Path passwordFile;

    @BeforeAll
    static void serve() throws Exception {
        pki = TestPki.generate();
        server = new FakeHttpsServer(pki.serverContext());
        keyFile = dir.resolve("es.key");
        Files.writeString(keyFile, KEY);
        passwordFile = dir.resolve("os.password");
        Files.writeString(passwordFile, PASSWORD);
    }

    @AfterAll
    static void stop() throws Exception {
        server.close();
    }

    @BeforeEach
    void fresh() {
        server.received.clear();
        server.accepts = null;
    }

    private static String url(String auth, Path secret) {
        return "https://" + auth + "localhost:" + server.port() + "/?provider=file&path="
                + secret.toString().replace('\\', '/') + "&tlsPin=" + pki.pin();
    }

    private static void expect(String authorization) {
        server.headerName = "Authorization";
        server.expected = authorization.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void theTypedClientIndexesWithTheApiKeyWrittenIn() throws Exception {
        expect("ApiKey " + KEY);
        // A placeholder for the same secret, in a document: it is stored as it is.
        String planted = SeclumeSslSocketFactory.placeholder("provider=file&path="
                + keyFile.toString().replace('\\', '/'));
        ElasticsearchClient es = SeclumeElasticsearch.client(url("", keyFile) + "&auth=apikey");
        try {
            assertEquals("c", es.info().clusterName());
            es.index(i -> i.index("orders").id("1").document(Map.of("note", planted)));
        } finally {
            es.close();
        }
        assertEquals(2, server.received.size());
        assertTrue(server.received.stream().allMatch(FakeHttpsServer.Received::authorized),
                "a request arrived without the key");
        String body = server.received.get(1).body();
        assertTrue(body.contains(planted) && !body.contains(KEY),
                "the document was rewritten - the key would have been indexed: " + body);
    }

    @Test
    void theRest5ClientAndTheRestClient() throws Exception {
        expect("Bearer " + KEY);
        try (Rest5Client client = SeclumeElasticsearch.rest5Client(url("", keyFile)
                + "&auth=bearer")) {
            assertEquals(200, client.performRequest(new Request("GET", "/"))
                    .getStatusCode());
        }
        try (org.elasticsearch.client.RestClient client = SeclumeElasticsearch.restClient(
                url("", keyFile) + "&auth=bearer")) {
            assertEquals(200, client.performRequest(new org.elasticsearch.client.Request("GET",
                    "/")).getStatusLine().getStatusCode());
        }
        assertEquals(2, server.received.size());
        assertTrue(server.received.stream().allMatch(FakeHttpsServer.Received::authorized));
    }

    @Test
    void openSearchWithBasic() throws Exception {
        expect("Basic " + Base64.getEncoder().encodeToString(("app:" + PASSWORD)
                .getBytes(StandardCharsets.UTF_8)));
        var os = SeclumeOpenSearch.client(url("app@", passwordFile) + "&auth=basic");
        try {
            assertEquals("c", os.info().clusterName());
        } finally {
            os._transport().close();
        }
        assertTrue(server.received.get(0).authorized(), "the password was not written in");
    }

    @Test
    void whatTheUrlRefuses() {
        String secret = "provider=file&path=/run/secrets/x";
        for (String url : new String[] {
            "http://es:9200/?auth=apikey&" + secret,
            "https://elastic:changeme@es:9200/?auth=basic&" + secret,
            "https://es:9200/?" + secret,
            "https://es:9200/?auth=basic&" + secret,
            "https://user@es:9200/?auth=apikey&" + secret,
            "https://es:9200/?auth=digest&" + secret,
            "https://es:9200/?auth=apikey",
            "https://es:99999/?auth=apikey&" + secret}) {
            assertThrows(IllegalArgumentException.class, () -> SearchUrl.parse(url), url);
        }
    }
}
