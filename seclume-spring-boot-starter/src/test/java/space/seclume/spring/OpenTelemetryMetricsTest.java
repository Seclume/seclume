package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.MapPropertySource;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.MetricData;
import io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader;

import space.seclume.tck.TestHosts;

/**
 * {@code seclume.metrics.opentelemetry=true} with an {@code OpenTelemetry}
 * bean: the application's own SDK receives the pool of every configured data
 * source under the connection-pool conventions. Without the property nothing
 * is started. Against the PostgreSQL the other starter tests use.
 */
class OpenTelemetryMetricsTest {

    private static final InMemoryMetricReader READER = InMemoryMetricReader.create();
    private static Path passwordFile;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(passwordFile != null,
                TestHosts.postgresPasswordFile() + " is not there");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(TestHosts.postgres(), TestHosts.postgresPort()),
                    1000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + TestHosts.postgres() + ":"
                    + TestHosts.postgresPort());
        }
    }

    /** The application's SDK, as a Spring application declares it. */
    @Configuration(proxyBeanMethods = false)
    static class Sdk {

        @Bean(destroyMethod = "close")
        OpenTelemetrySdk openTelemetry() {
            return OpenTelemetrySdk.builder().setMeterProvider(
                    SdkMeterProvider.builder().registerMetricReader(READER).build()).build();
        }
    }

    private static AnnotationConfigApplicationContext context(boolean enabled) {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("seclume.datasources.main.url", "jdbc:seclume:postgresql://"
                + TestHosts.postgres() + ":" + TestHosts.postgresPort() + "/seclume_test");
        properties.put("seclume.datasources.main.username", "seclume_test");
        properties.put("seclume.datasources.main.secret.provider", "file");
        properties.put("seclume.datasources.main.secret.path",
                passwordFile.toString().replace('\\', '/'));
        if (enabled) {
            properties.put("seclume.metrics.opentelemetry", "true");
        }
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test", properties));
        context.register(Sdk.class, SeclumeAutoConfiguration.class);
        context.refresh();
        return context;
    }

    @Test
    void thePoolIsMeasuredThroughTheApplicationsSdk() throws Exception {
        try (AnnotationConfigApplicationContext context = context(true)) {
            SeclumeOpenTelemetryMetrics metrics = context.getBean(SeclumeOpenTelemetryMetrics.class);
            assertEquals(1, metrics.pools());
            assertTrue(context.getBean(OpenTelemetry.class) instanceof OpenTelemetrySdk);
            try (Connection connection = context.getBean(DataSource.class).getConnection()) {
                assertTrue(connection.isValid(5));
                MetricData count = READER.collectAllMetrics().stream()
                        .filter(m -> m.getName().equals("db.client.connection.count"))
                        .findFirst().orElseThrow(() -> new AssertionError("no pool metrics"));
                long used = count.getLongSumData().getPoints().stream()
                        .filter(p -> "used".equals(p.getAttributes().get(
                                AttributeKey.stringKey("db.client.connection.state"))))
                        .filter(p -> "seclume-main".equals(p.getAttributes().get(
                                AttributeKey.stringKey("db.client.connection.pool.name"))))
                        .mapToLong(p -> p.getValue()).sum();
                assertEquals(1, used);
            }
        }
    }

    @Test
    void withoutThePropertyNothingIsStarted() {
        try (AnnotationConfigApplicationContext context = context(false)) {
            assertEquals(0, context.getBeansOfType(SeclumeOpenTelemetryMetrics.class).size());
        }
    }
}
