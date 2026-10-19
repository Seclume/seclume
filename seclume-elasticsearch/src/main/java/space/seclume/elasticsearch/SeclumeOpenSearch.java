package space.seclume.elasticsearch;

import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.message.BasicHeader;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.transport.httpclient5.ApacheHttpClient5Transport;
import org.opensearch.client.transport.httpclient5.ApacheHttpClient5TransportBuilder;

import space.seclume.http.SeclumeSslContext;

/**
 * The official OpenSearch Java client (opensearch-java 3) with the password
 * or token off the heap, the same way as {@link SeclumeElasticsearch}: a
 * placeholder in the client's {@code Authorization} header, the secret
 * written in by seclume's TLS 1.3 engine. OpenSearch's security plugin takes
 * {@code auth=basic} and {@code auth=bearer} (a JWT); it has no Elasticsearch
 * API keys.
 *
 * <pre>{@code
 * OpenSearchClient os = SeclumeOpenSearch.client(
 *         "https://app@os.example.com:9200/?auth=basic&provider=file&path=/run/secrets/os");
 * }</pre>
 */
public final class SeclumeOpenSearch {

    private SeclumeOpenSearch() {
    }

    public static OpenSearchClient client(String url) {
        return new OpenSearchClient(transport(url));
    }

    /**
     * Amazon OpenSearch Service, signed with SigV4, the secret key off the heap:
     *
     * <pre>{@code
     * OpenSearchClient os = SeclumeOpenSearch.awsClient("https://search-shop-abc.eu-central-1.es.amazonaws.com"
     *         + "/?auth=aws&region=eu-central-1&access-key-id=AKIA...&provider=file&path=/run/secrets/aws");
     * }</pre>
     *
     * <p>{@code service=aoss} for OpenSearch Serverless ({@code es} by
     * default); {@code credentials=instance}, {@code container} or
     * {@code web-identity} for a workload's temporary credentials, as for
     * {@code SeclumeAws}. The client is opensearch-java's own
     * {@code AwsSdk2Transport}, which signs with the SDK's signer and offers no
     * way to replace it: it is given a placeholder key, and its HTTP client -
     * seclume's - drops that signature and signs every request again from
     * native memory ({@code SeclumeAws.resigning}).
     */
    public static OpenSearchClient awsClient(String url) {
        return new OpenSearchClient(awsTransport(url));
    }

    /** The transport of {@link #awsClient}, for an application that builds its own client. */
    public static org.opensearch.client.transport.aws.AwsSdk2Transport awsTransport(String url) {
        if (url == null || !url.startsWith("https://")) {
            throw new IllegalArgumentException("an Amazon OpenSearch URL starts with https://");
        }
        String rest = url.substring("https://".length());
        int question = rest.indexOf('?');
        String location = question < 0 ? rest : rest.substring(0, question);
        String host = location.contains("/") ? location.substring(0, location.indexOf('/'))
                : location;
        if (host.isEmpty() || host.contains("@")) {
            throw new IllegalArgumentException("an Amazon OpenSearch URL names the domain's "
                    + "endpoint and nothing before it: '" + host + "'");
        }
        String service = "es";
        boolean aws = false;
        StringBuilder spec = new StringBuilder();
        for (String pair : (question < 0 ? "" : rest.substring(question + 1)).split("&")) {
            if (pair.equals("auth=aws")) {
                aws = true;
            } else if (pair.startsWith("service=")) {
                service = pair.substring("service=".length());
            } else if (!pair.isEmpty()) {
                spec.append(spec.isEmpty() ? "" : "&").append(pair);
            }
        }
        if (!aws) {
            throw new IllegalArgumentException("auth=aws: Amazon OpenSearch signs with SigV4 - "
                    + "for a password or token use SeclumeOpenSearch.client(url)");
        }
        if (!service.equals("es") && !service.equals("aoss")) {
            throw new IllegalArgumentException("service=" + service + " is neither es (a "
                    + "domain) nor aoss (Serverless)");
        }
        space.seclume.aws.SeclumeAws.Resigning resigning = space.seclume.aws.SeclumeAws
                .resigning(spec.toString(), service);
        return new org.opensearch.client.transport.aws.AwsSdk2Transport(resigning.httpClient(),
                host, service, resigning.region(),
                org.opensearch.client.transport.aws.AwsSdk2TransportOptions.builder()
                        .setCredentials(resigning.credentials())
                        .setMapper(new JacksonJsonpMapper())
                        .build());
    }

    /** The transport on Apache HttpClient 5, for an application that builds its own client. */
    public static ApacheHttpClient5Transport transport(String url) {
        SearchUrl parsed = SearchUrl.parse(url);
        var tls = ClientTlsStrategyBuilder.create()
                .setSslContext(SeclumeSslContext.of(parsed.tls()))
                .buildAsync();
        HttpHost[] hosts = parsed.hosts().stream()
                .map(h -> new HttpHost("https", h.name(), h.port()))
                .toArray(HttpHost[]::new);
        ApacheHttpClient5TransportBuilder builder = ApacheHttpClient5TransportBuilder
                .builder(hosts)
                .setMapper(new JacksonJsonpMapper())
                .setDefaultHeaders(new Header[] {new BasicHeader("Authorization",
                        parsed.authorization())})
                .setHttpClientConfigCallback(client -> client.setConnectionManager(
                        PoolingAsyncClientConnectionManagerBuilder.create()
                                .setTlsStrategy(tls).build()));
        if (!parsed.pathPrefix().isEmpty()) {
            builder.setPathPrefix(parsed.pathPrefix());
        }
        return builder.build();
    }
}
