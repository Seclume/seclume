package space.seclume.elasticsearch;

import javax.net.ssl.SSLContext;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.json.jackson.JacksonJsonpMapper;
import co.elastic.clients.transport.rest5_client.Rest5ClientTransport;
import co.elastic.clients.transport.rest5_client.low_level.Rest5Client;

import space.seclume.http.SeclumeSslContext;
import space.seclume.http.SeclumeSslSocketFactory;

/**
 * The official Elasticsearch Java clients with the API key, token or
 * password off the heap.
 *
 * <pre>{@code
 * ElasticsearchClient es = SeclumeElasticsearch.client(
 *         "https://es.example.com:9200/?auth=apikey&provider=file&path=/run/secrets/es-key");
 * }</pre>
 *
 * <p>The client never holds the secret: it is given a placeholder in its
 * {@code Authorization} header, and seclume's TLS 1.3 engine writes the
 * secret in from native memory as each request head goes into the cipher
 * ({@link SeclumeSslContext}). Bodies are not touched - a document that
 * happens to contain the placeholder is stored with the placeholder. The
 * URL is {@link SearchUrl}'s.
 */
public final class SeclumeElasticsearch {

    private SeclumeElasticsearch() {
    }

    /** The typed client (elasticsearch-java 9), on {@link #rest5Client}. */
    public static ElasticsearchClient client(String url) {
        return new ElasticsearchClient(new Rest5ClientTransport(rest5Client(url),
                new JacksonJsonpMapper()));
    }

    /** The low-level client of elasticsearch-java 9, on Apache HttpClient 5. */
    public static Rest5Client rest5Client(String url) {
        SearchUrl parsed = SearchUrl.parse(url);
        SSLContext tls = SeclumeSslContext.of(parsed.tls());
        org.apache.hc.core5.http.HttpHost[] hosts = parsed.hosts().stream()
                .map(h -> new org.apache.hc.core5.http.HttpHost("https", h.name(), h.port()))
                .toArray(org.apache.hc.core5.http.HttpHost[]::new);
        var builder = Rest5Client.builder(hosts)
                .setSSLContext(tls)
                .setDefaultHeaders(new org.apache.hc.core5.http.Header[] {
                    new org.apache.hc.core5.http.message.BasicHeader("Authorization",
                            parsed.authorization())});
        if (!parsed.pathPrefix().isEmpty()) {
            builder.setPathPrefix(parsed.pathPrefix());
        }
        return builder.build();
    }

    /**
     * The low-level {@code RestClient} (elasticsearch-rest-client, on
     * HttpAsyncClient 4) - what Elasticsearch 8's clients and Spring Data
     * Elasticsearch before 6 are built on.
     */
    public static org.elasticsearch.client.RestClient restClient(String url) {
        SearchUrl parsed = SearchUrl.parse(url);
        SSLContext tls = SeclumeSslContext.of(parsed.tls());
        // The engine checks the certificate and the name itself; this only
        // keeps HttpAsyncClient from asking JSSE a second time.
        javax.net.ssl.HostnameVerifier checked = SeclumeSslSocketFactory.of(parsed.tls())
                .hostnameVerifier();
        org.apache.http.HttpHost[] hosts = parsed.hosts().stream()
                .map(h -> new org.apache.http.HttpHost(h.name(), h.port(), "https"))
                .toArray(org.apache.http.HttpHost[]::new);
        var builder = org.elasticsearch.client.RestClient.builder(hosts)
                .setDefaultHeaders(new org.apache.http.Header[] {
                    new org.apache.http.message.BasicHeader("Authorization",
                            parsed.authorization())})
                .setHttpClientConfigCallback(client -> client.setSSLContext(tls)
                        .setSSLHostnameVerifier(checked));
        if (!parsed.pathPrefix().isEmpty()) {
            builder.setPathPrefix(parsed.pathPrefix());
        }
        return builder.build();
    }
}
