package space.seclume.spring;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * Elasticsearch and OpenSearch with the API key, token or password off the
 * heap:
 *
 * <pre>
 * seclume.elasticsearch.url=https://es.example.com:9200/?auth=apikey&amp;provider=file&amp;path=/run/secrets/es-key
 * seclume.opensearch.url=https://app@os.example.com:9200/?auth=basic&amp;provider=file&amp;path=/run/secrets/os
 * seclume.opensearch.url=https://search-shop.eu-central-1.es.amazonaws.com/?auth=aws&amp;region=eu-central-1&amp;credentials=container
 * </pre>
 *
 * <p>For Elasticsearch a {@code Rest5Client}: Spring Boot's own client
 * configuration steps aside, and builds its transport, its
 * {@code ElasticsearchClient} and Spring Data Elasticsearch on this one. For
 * OpenSearch an {@code OpenSearchClient}, for which Spring Boot has nothing
 * of its own. Both from {@code seclume-elasticsearch}: the secret is written
 * into each request by seclume's TLS engine, never held by the client.
 *
 * <p>{@code spring.elasticsearch.password} and {@code spring.elasticsearch.api-key}
 * are refused while seclume configures Elasticsearch (see {@link InlineSecrets}).
 */
@AutoConfiguration(beforeName =
        "org.springframework.boot.elasticsearch.autoconfigure.ElasticsearchRestClientAutoConfiguration")
@ConditionalOnClass(name = "space.seclume.elasticsearch.SeclumeElasticsearch")
public class SeclumeSearchAutoConfiguration {

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "co.elastic.clients.transport.rest5_client.low_level.Rest5Client")
    @ConditionalOnProperty("seclume.elasticsearch.url")
    static class Elasticsearch {

        @Bean(destroyMethod = "close")
        @ConditionalOnMissingBean(
                co.elastic.clients.transport.rest5_client.low_level.Rest5Client.class)
        co.elastic.clients.transport.rest5_client.low_level.Rest5Client elasticsearchRestClient(
                Environment environment) {
            InlineSecrets.refuse(environment, "seclume.elasticsearch.url", new String[] {
                "spring.elasticsearch.password", "spring.elasticsearch.api-key"},
                "spring.elasticsearch.uris");
            return space.seclume.elasticsearch.SeclumeElasticsearch.rest5Client(
                    environment.getRequiredProperty("seclume.elasticsearch.url"));
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.opensearch.client.opensearch.OpenSearchClient")
    @ConditionalOnProperty("seclume.opensearch.url")
    static class OpenSearch {

        @Bean
        @ConditionalOnMissingBean(org.opensearch.client.opensearch.OpenSearchClient.class)
        org.opensearch.client.opensearch.OpenSearchClient openSearchClient(
                Environment environment) {
            String url = environment.getRequiredProperty("seclume.opensearch.url");
            // Amazon OpenSearch Service signs with SigV4 instead of a password or token.
            return url.contains("auth=aws")
                    ? space.seclume.elasticsearch.SeclumeOpenSearch.awsClient(url)
                    : space.seclume.elasticsearch.SeclumeOpenSearch.client(url);
        }
    }
}
