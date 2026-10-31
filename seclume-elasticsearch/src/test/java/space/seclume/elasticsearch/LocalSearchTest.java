package space.seclume.elasticsearch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.Refresh;
import co.elastic.clients.transport.rest5_client.low_level.Request;

import space.seclume.http.SeclumeSslSocketFactory;
import space.seclume.tck.TestHosts;

/**
 * Against a real Elasticsearch 9 (API key) and OpenSearch 3 (admin's
 * password), both with TLS - the fixtures of
 * {@code .github/scripts/search_fixtures.sh}: a document indexed, read back
 * and searched for; a document holding a placeholder stored with the
 * placeholder, not the key; and a wrong key refused by the server.
 */
@Timeout(180)
class LocalSearchTest {

    private static final String HOST = System.getProperty("seclume.search.host",
            TestHosts.database());

    private static Path find(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static void reachable(int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(HOST, port), 2000);
        } catch (IOException e) {
            assumeTrue(false, "nothing on " + HOST + ":" + port);
        }
    }

    private static String slashes(Path path) {
        return path.toString().replace('\\', '/');
    }

    private static String elasticsearch(Path key) {
        Path ca = find(".local-es-ca.pem");
        assumeTrue(key != null && ca != null, "no Elasticsearch fixture files");
        reachable(9201);
        return "https://" + HOST + ":9201/?auth=apikey&provider=file&path=" + slashes(key)
                + "&tlsRootCert=" + slashes(ca);
    }

    @Test
    void elasticsearchWithAnApiKey() throws Exception {
        Path key = find(".local-es-apikey");
        String url = elasticsearch(key);
        String index = "zl_seclume_" + Long.toHexString(System.nanoTime());
        // A placeholder for the same key, inside a document: stored as it is.
        String planted = SeclumeSslSocketFactory.placeholder("provider=file&path="
                + slashes(key));
        ElasticsearchClient es = SeclumeElasticsearch.client(url);
        try {
            assertTrue(es.ping().value());
            es.index(i -> i.index(index).id("1").refresh(Refresh.True)
                    .document(Map.of("sku", "a-1", "note", planted)));
            @SuppressWarnings("unchecked")
            Map<String, Object> stored = es.get(g -> g.index(index).id("1"), Map.class).source();
            assertEquals(planted, stored.get("note"),
                    "the document was rewritten on its way - the key would have been indexed");
            assertEquals(1, es.search(s -> s.index(index).query(q -> q.term(t -> t.field("sku.keyword")
                    .value("a-1"))), Map.class).hits().total().value());
        } finally {
            es.indices().delete(d -> d.index(index));
            es.close();
        }
        try (var client = SeclumeElasticsearch.restClient(url)) {
            assertEquals(200, client.performRequest(new org.elasticsearch.client.Request("GET",
                    "/")).getStatusLine().getStatusCode());
        }
        try (var client = SeclumeElasticsearch.rest5Client(url)) {
            assertEquals(200, client.performRequest(new Request("GET", "/")).getStatusCode());
        }
    }

    /** Encrypted fields in a real cluster: stored as ciphertext, found by a terms query, opened again. */
    @Test
    void encryptedFieldsAreStoredSealedAndFoundByTheirTerms() throws Exception {
        Path key = find(".local-es-apikey");
        String url = elasticsearch(key);
        String index = "zl_seclume_enc_" + Long.toHexString(System.nanoTime());
        space.seclume.secret.SecretProvider ringKey = new space.seclume.secret.SecretProvider() {
            @Override
            public int writeSecret(java.lang.foreign.MemorySegment target) {
                for (int i = 0; i < 32; i++) {
                    target.set(java.lang.foreign.ValueLayout.JAVA_BYTE, i, (byte) (i * 7 + 1));
                }
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        };
        ElasticsearchClient es = SeclumeElasticsearch.client(url);
        try (space.seclume.field.FieldKeys keys = space.seclume.field.FieldKeys.builder().key(1, ringKey).build()) {
            EncryptedDocument patients = EncryptedDocument.of(keys, index)
                    .field("ssn", space.seclume.field.EncryptedColumn.Mode.DETERMINISTIC)
                    .field("diagnosis", space.seclume.field.EncryptedColumn.Mode.RANDOMIZED);
            es.index(i -> i.index(index).id("1").refresh(Refresh.True).document(patients.encrypt(
                    Map.of("name", "Alice", "ssn", "123-45-6789", "diagnosis", "zl-es-canary"))));
            es.index(i -> i.index(index).id("2").refresh(Refresh.True).document(patients.encrypt(
                    Map.of("name", "Bob", "ssn", "987-65-4321", "diagnosis", "other"))));
            @SuppressWarnings("unchecked")
            Map<String, Object> stored = es.get(g -> g.index(index).id("1"), Map.class).source();
            assertTrue(!stored.toString().contains("zl-es-canary") && !stored.toString().contains("123-45-6789"),
                    "the cluster holds the fields in the clear: " + stored);
            var hits = es.search(s -> s.index(index).query(q -> q.terms(t -> t.field("ssn.keyword")
                    .terms(v -> v.value(patients.searchTerms("ssn", "123-45-6789").stream()
                            .map(co.elastic.clients.elasticsearch._types.FieldValue::of).toList())))),
                    Map.class).hits().hits();
            assertEquals(1, hits.size());
            @SuppressWarnings("unchecked")
            Map<String, Object> found = patients.decrypt((Map<String, Object>) hits.get(0).source());
            assertEquals("Alice", found.get("name"));
            assertEquals("zl-es-canary", found.get("diagnosis"));
        } finally {
            es.indices().delete(d -> d.index(index));
            es.close();
        }
    }

    /** The control: the same way with a key the server does not know is refused by it. */
    @Test
    void aWrongKeyIsRefusedByTheServer(@TempDir Path dir) throws Exception {
        Path wrong = dir.resolve("wrong.key");
        Files.writeString(wrong, "bm90OmFrZXk=");
        String url = elasticsearch(wrong);
        ElasticsearchClient es = SeclumeElasticsearch.client(url);
        try {
            Exception refused = assertThrows(Exception.class, () -> es.info());
            assertTrue(String.valueOf(refused.getMessage()).contains("unable to authenticate"),
                    String.valueOf(refused.getMessage()));
        } finally {
            es.close();
        }
    }

    @Test
    void openSearchWithBasic() throws Exception {
        Path password = find(".local-os-password");
        Path ca = find(".local-es-ca.pem");
        assumeTrue(password != null && ca != null, "no OpenSearch fixture files");
        reachable(9202);
        String url = "https://admin@" + HOST + ":9202/?auth=basic&provider=file&path="
                + slashes(password) + "&tlsRootCert=" + slashes(ca);
        String index = "zl_seclume_" + Long.toHexString(System.nanoTime());
        var os = SeclumeOpenSearch.client(url);
        try {
            assertTrue(os.info().version().distribution().contains("opensearch"));
            os.index(i -> i.index(index).id("1")
                    .refresh(org.opensearch.client.opensearch._types.Refresh.True)
                    .document(Map.of("sku", "a-1")));
            assertEquals("a-1", os.get(g -> g.index(index).id("1"), Map.class).source()
                    .get("sku"));
        } finally {
            os.indices().delete(d -> d.index(index));
            os._transport().close();
        }
    }
}
