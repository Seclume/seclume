package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

import co.elastic.clients.transport.rest5_client.low_level.Request;
import co.elastic.clients.transport.rest5_client.low_level.Rest5Client;

import space.seclume.tck.TestHosts;

/** MongoDB, Elasticsearch/OpenSearch, RabbitMQ, NATS and Redis from application.properties. */
class DataServicesAutoConfigurationTest {

    @TempDir
    Path directory;

    private static AnnotationConfigApplicationContext context(Class<?> configuration,
                                                              String... pairs) {
        Map<String, Object> properties = new HashMap<>();
        for (String pair : pairs) {
            properties.put(pair.substring(0, pair.indexOf('=')),
                    pair.substring(pair.indexOf('=') + 1));
        }
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test", properties));
        context.register(configuration);
        context.refresh();
        return context;
    }

    private String secret(String name) throws IOException {
        Path file = directory.resolve(name);
        Files.writeString(file, "a-secret-for-this-test");
        return "provider=file&path=" + file.toString().replace('\\', '/');
    }

    private static Path find(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static boolean reachable(String host, int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** What a refused context says, wherever Spring wrapped it. */
    private static String refusal(Runnable start) {
        BeanCreationException failed = assertThrows(BeanCreationException.class, start::run);
        Throwable cause = failed;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause.getMessage();
    }

    // ---- MongoDB -----------------------------------------------------------------------

    @Test
    void mongoClientsAreSeclumes() throws Exception {
        String url = "mongodb://app@127.0.0.1:1/?authSource=admin&" + secret("mongo")
                + "&serverSelectionTimeoutMS=500";
        try (AnnotationConfigApplicationContext context = context(
                SeclumeMongoAutoConfiguration.class, "seclume.mongodb.url=" + url)) {
            Object sync = context.getBean(com.mongodb.client.MongoClient.class);
            Object reactive = context.getBean(
                    com.mongodb.reactivestreams.client.MongoClient.class);
            assertTrue(sync.getClass().getName().startsWith("space.seclume.mongodb.driver."),
                    "the sync client is " + sync.getClass());
            assertTrue(reactive.getClass().getName().startsWith("space.seclume.mongodb."),
                    "the reactive client is " + reactive.getClass());
        }
    }

    @Test
    void aMongoPasswordInSpringsSettingsIsRefused() throws Exception {
        String url = "mongodb://app@127.0.0.1:1/?" + secret("mongo2");
        assertTrue(refusal(() -> context(SeclumeMongoAutoConfiguration.class,
                "seclume.mongodb.url=" + url, "spring.mongodb.password=hunter2").close())
                .contains("spring.mongodb.password is set"));
        assertTrue(refusal(() -> context(SeclumeMongoAutoConfiguration.class,
                "seclume.mongodb.url=" + url,
                "spring.mongodb.uri=mongodb://app:hunter2@db/shop").close())
                .contains("spring.mongodb.uri carries a password"));
    }

    @Test
    void withoutTheUrlNothingIsMade() {
        try (AnnotationConfigApplicationContext context = context(
                SeclumeMongoAutoConfiguration.class)) {
            assertEquals(0, context.getBeansOfType(com.mongodb.client.MongoClient.class).size());
        }
    }

    // ---- Elasticsearch and OpenSearch ------------------------------------------------------

    @Test
    void searchClientsFromTheUrls() throws Exception {
        try (AnnotationConfigApplicationContext context = context(
                SeclumeSearchAutoConfiguration.class,
                "seclume.elasticsearch.url=https://127.0.0.1:1/?auth=apikey&" + secret("es"),
                "seclume.opensearch.url=https://app@127.0.0.1:1/?auth=basic&" + secret("os"))) {
            assertEquals(1, context.getBeansOfType(Rest5Client.class).size());
            assertEquals(1, context.getBeansOfType(
                    org.opensearch.client.opensearch.OpenSearchClient.class).size());
        }
    }

    @Test
    void anElasticsearchPasswordInSpringsSettingsIsRefused() throws Exception {
        String url = "https://127.0.0.1:1/?auth=apikey&" + secret("es2");
        assertTrue(refusal(() -> context(SeclumeSearchAutoConfiguration.class,
                "seclume.elasticsearch.url=" + url, "spring.elasticsearch.password=x").close())
                .contains("spring.elasticsearch.password is set"));
    }

    /** Against the fixture of search_fixtures.sh, when it is there: the key really is written in. */
    @Test
    void theRestClientReachesElasticsearch() throws Exception {
        String host = System.getProperty("seclume.search.host", TestHosts.database());
        Path key = find(".local-es-apikey");
        Path ca = find(".local-es-ca.pem");
        assumeTrue(key != null && ca != null && reachable(host, 9201), "no Elasticsearch");
        try (AnnotationConfigApplicationContext context = context(
                SeclumeSearchAutoConfiguration.class, "seclume.elasticsearch.url=https://"
                        + host + ":9201/?auth=apikey&provider=file&path="
                        + key.toString().replace('\\', '/') + "&tlsRootCert="
                        + ca.toString().replace('\\', '/'))) {
            assertEquals(200, context.getBean(Rest5Client.class)
                    .performRequest(new Request("GET", "/")).getStatusCode());
        }
    }

    // ---- RabbitMQ, NATS, Redis --------------------------------------------------------------

    @Test
    void rabbitConnectionFactoryOnSeclumesClient() throws Exception {
        try (AnnotationConfigApplicationContext context = context(
                SeclumeMessagingAutoConfiguration.class,
                "seclume.rabbitmq.url=amqps://mq.example.invalid/orders?user=app&" + secret("mq"))) {
            CachingConnectionFactory factory = context.getBean(CachingConnectionFactory.class);
            assertEquals("mq.example.invalid", factory.getHost());
            assertEquals("orders", factory.getVirtualHost());
        }
        String url = "amqps://mq.example.invalid/orders?user=app&" + secret("mq2");
        assertTrue(refusal(() -> context(SeclumeMessagingAutoConfiguration.class,
                "seclume.rabbitmq.url=" + url, "spring.rabbitmq.password=guest").close())
                .contains("spring.rabbitmq.password is set"));
    }

    @Test
    void natsIsOnlyMadeWithItsUrl() {
        try (AnnotationConfigApplicationContext context = context(
                SeclumeMessagingAutoConfiguration.class)) {
            assertEquals(0, context.getBeansOfType(io.nats.client.Connection.class).size());
        }
    }

    @Test
    void redisConnectionFactoryOnSeclumesLettuce() throws Exception {
        try (AnnotationConfigApplicationContext context = context(
                SeclumeRedisAutoConfiguration.class,
                "seclume.redis.url=rediss://cache.example.invalid:6380?user=orders&"
                        + secret("redis"))) {
            LettuceConnectionFactory factory = context.getBean(LettuceConnectionFactory.class);
            assertEquals("cache.example.invalid", factory.getHostName());
            assertEquals(6380, factory.getPort());
            char[] password = factory.getPassword() == null ? new char[0]
                    : factory.getPassword().toCharArray();
            assertTrue(new String(password).startsWith("seclume-redis-"),
                    "Spring Data Redis holds something other than the placeholder");
        }
        String url = "redis://cache.example.invalid?" + secret("redis2");
        assertTrue(refusal(() -> context(SeclumeRedisAutoConfiguration.class,
                "seclume.redis.url=" + url, "spring.data.redis.password=x").close())
                .contains("spring.data.redis.password is set"));
    }
}
