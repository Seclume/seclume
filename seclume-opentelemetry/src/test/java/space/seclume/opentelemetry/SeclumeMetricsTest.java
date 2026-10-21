package space.seclume.opentelemetry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Collection;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.HistogramPointData;
import io.opentelemetry.sdk.metrics.data.LongPointData;
import io.opentelemetry.sdk.metrics.data.MetricData;
import io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader;

import space.seclume.jfr.SeclumeEvents;

/**
 * The drivers' events, as an application's OpenTelemetry SDK receives them:
 * real {@code space.seclume} events committed in this process, read back
 * from an in-memory reader. Names and attributes are the starter's; durations
 * are histograms in seconds.
 */
@Isolated("a recording stream sees every seclume event of the JVM")
@Timeout(60)
class SeclumeMetricsTest {

    private InMemoryMetricReader reader;
    private OpenTelemetrySdk sdk;

    @BeforeEach
    void anSdk() {
        reader = InMemoryMetricReader.create();
        sdk = OpenTelemetrySdk.builder()
                .setMeterProvider(SdkMeterProvider.builder().registerMetricReader(reader).build())
                .build();
    }

    @AfterEach
    void closeIt() {
        sdk.close();
    }

    @Test
    void aLoginIsAHistogramInSecondsWithItsKindMethodAndOutcome() throws Exception {
        try (SeclumeMetrics _ = SeclumeMetrics.start(sdk)) {
            awaitStarted();
            SeclumeEvents.Authentication login = new SeclumeEvents.Authentication();
            login.begin();
            Thread.sleep(5);
            login.kind = "postgresql";
            login.server = "db.example.com:5432";
            login.method = "SCRAM-SHA-256";
            login.succeeded = true;
            login.end();
            login.commit();

            MetricData data = await("seclume.authentications");
            assertEquals("s", data.getUnit());
            HistogramPointData point = data.getHistogramData().getPoints().iterator().next();
            assertEquals(1, point.getCount());
            assertTrue(point.getSum() > 0.004 && point.getSum() < 5, "seconds: " + point.getSum());
            assertEquals("postgresql", point.getAttributes().get(AttributeKey.stringKey("kind")));
            assertEquals("SCRAM-SHA-256",
                    point.getAttributes().get(AttributeKey.stringKey("method")));
            assertEquals("ok", point.getAttributes().get(AttributeKey.stringKey("outcome")));
            assertEquals(3, point.getAttributes().size(), "the server is not an attribute");
        }
    }

    /** A failed rotation counts, under its watch - and its reason stays in the recording. */
    @Test
    void aRotationCountsWithoutItsReason() throws Exception {
        try (SeclumeMetrics _ = SeclumeMetrics.start(sdk)) {
            awaitStarted();
            SeclumeEvents.SecretRotation rotation = new SeclumeEvents.SecretRotation();
            rotation.begin();
            rotation.watch = "tls-key";
            rotation.succeeded = false;
            rotation.reason = "IllegalStateException: the key does not match its certificate";
            rotation.end();
            rotation.commit();

            MetricData data = await("seclume.secret.rotations");
            LongPointData point = data.getLongSumData().getPoints().iterator().next();
            assertEquals(1, point.getValue());
            assertEquals("tls-key", point.getAttributes().get(AttributeKey.stringKey("watch")));
            assertEquals("failed", point.getAttributes().get(AttributeKey.stringKey("outcome")));
            assertFalse(point.getAttributes().toString().contains("does not match"),
                    point.getAttributes().toString());
        }
    }

    /** A statement below the threshold is not measured; one above is, by its shape. */
    @Test
    void onlySlowStatementsAreMeasured() throws Exception {
        try (SeclumeMetrics _ = SeclumeMetrics.start(sdk, Duration.ofMillis(20), 100)) {
            awaitStarted();
            query("select ? from fast", 0);
            query("select ? from slow", 40);

            MetricData data = await("seclume.query.slow");
            Collection<HistogramPointData> points = data.getHistogramData().getPoints();
            assertEquals(1, points.size(), points.toString());
            HistogramPointData point = points.iterator().next();
            assertEquals("select ? from slow",
                    point.getAttributes().get(AttributeKey.stringKey("fingerprint")));
            assertEquals("ok", point.getAttributes().get(AttributeKey.stringKey("outcome")));
        }
    }

    /** Past the bound, shapes are counted as "other" - the totals stay right. */
    @Test
    void statementShapesAreBounded() {
        try (SeclumeMetrics metrics = SeclumeMetrics.start(sdk, Duration.ofMillis(10), 2)) {
            assertEquals("a", metrics.bounded("a"));
            assertEquals("b", metrics.bounded("b"));
            assertEquals(SeclumeMetrics.OTHER, metrics.bounded("c"));
            assertEquals("a", metrics.bounded("a"), "a named shape keeps its name");
            assertEquals(SeclumeMetrics.OTHER, metrics.bounded(""));
        }
    }

    /** Before start nothing is measured, and after close nothing more. */
    @Test
    void nothingIsMeasuredUnlessStarted() throws Exception {
        SeclumeEvents.SecretUse before = new SeclumeEvents.SecretUse();
        before.kind = "smtp";
        before.mechanism = "XOAUTH2";
        before.commit();
        assertTrue(reader.collectAllMetrics().isEmpty());

        SeclumeMetrics metrics = SeclumeMetrics.start(sdk);
        awaitStarted();
        metrics.close();
        SeclumeEvents.SecretUse after = new SeclumeEvents.SecretUse();
        after.kind = "smtp";
        after.mechanism = "XOAUTH2";
        after.commit();
        Thread.sleep(1500);
        assertFalse(reader.collectAllMetrics().stream()
                .anyMatch(m -> m.getName().equals("seclume.secret.uses")));
    }

    private static void query(String fingerprint, long millis) throws InterruptedException {
        SeclumeEvents.Query query = new SeclumeEvents.Query();
        query.begin();
        Thread.sleep(millis);
        query.kind = "postgresql";
        query.fingerprint = fingerprint;
        query.end();
        if (query.shouldCommit()) {
            query.commit();
        }
    }

    /**
     * The stream is started asynchronously; an event committed before it
     * reads would be lost to the test, not to an application. A first marker
     * event that arrives tells that it reads.
     */
    private void awaitStarted() throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (System.nanoTime() < deadline) {
            SeclumeEvents.Signature marker = new SeclumeEvents.Signature();
            marker.algorithm = "marker";
            marker.operation = "start";
            marker.succeeded = true;
            marker.commit();
            Thread.sleep(200);
            if (find("seclume.signatures").isPresent()) {
                return;
            }
        }
        throw new AssertionError("the recording stream never delivered an event");
    }

    private MetricData await(String name) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (System.nanoTime() < deadline) {
            Optional<MetricData> found = find(name);
            if (found.isPresent()) {
                return found.get();
            }
            Thread.sleep(100);
        }
        throw new AssertionError(name + " was never recorded");
    }

    private Optional<MetricData> find(String name) {
        return reader.collectAllMetrics().stream().filter(m -> m.getName().equals(name))
                .filter(m -> m.getInstrumentationScopeInfo().getName()
                        .equals(SeclumeMetrics.SCOPE))
                .findFirst();
    }
}
