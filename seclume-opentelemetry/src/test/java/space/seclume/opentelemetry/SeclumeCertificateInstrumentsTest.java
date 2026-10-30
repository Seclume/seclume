package space.seclume.opentelemetry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.DoublePointData;
import io.opentelemetry.sdk.metrics.data.LongPointData;
import io.opentelemetry.sdk.metrics.data.MetricData;
import io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader;

/**
 * Two certificates read through the gauges: the seconds left and whether the
 * last renewal failed, per bundle, read afresh at each collection - a
 * certificate that is not there left out - and nothing once closed.
 */
class SeclumeCertificateInstrumentsTest {

    private static final AttributeKey<String> BUNDLE = AttributeKey.stringKey("bundle");

    @Test
    void certificatesAreReadWhenCollected() throws Exception {
        InMemoryMetricReader reader = InMemoryMetricReader.create();
        Map<String, SeclumeCertificateInstruments.Reading> listed = new HashMap<>();
        listed.put("orders.svc", new SeclumeCertificateInstruments.Reading(
                Instant.now().plus(Duration.ofHours(2)), false));
        try (OpenTelemetrySdk sdk = OpenTelemetrySdk.builder().setMeterProvider(
                SdkMeterProvider.builder().registerMetricReader(reader).build()).build()) {
            AutoCloseable instruments = SeclumeCertificateInstruments.observe(sdk,
                    Map.of("web", "orders.svc", "mesh", "spiffe://example.org/orders"),
                    listed::get);

            Collection<MetricData> first = reader.collectAllMetrics();
            MetricData expiry = metric(first, "seclume.certificate.expiry");
            assertEquals("s", expiry.getUnit());
            assertEquals(1, expiry.getDoubleGaugeData().getPoints().size(),
                    "a certificate not there is left out");
            DoublePointData web = expiry.getDoubleGaugeData().getPoints().iterator().next();
            assertEquals("web", web.getAttributes().get(BUNDLE));
            assertTrue(web.getValue() > 7000 && web.getValue() <= 7200, "" + web.getValue());
            assertEquals(0, failing(first, "web"));

            // The SVID arrives, and the Vault certificate's renewal starts failing.
            listed.put("spiffe://example.org/orders", new SeclumeCertificateInstruments.Reading(
                    Instant.now().plus(Duration.ofMinutes(30)), false));
            listed.put("orders.svc", new SeclumeCertificateInstruments.Reading(
                    Instant.now().plus(Duration.ofHours(1)), true));
            Collection<MetricData> second = reader.collectAllMetrics();
            assertEquals(2, metric(second, "seclume.certificate.expiry").getDoubleGaugeData()
                    .getPoints().size());
            assertEquals(1, failing(second, "web"));
            assertEquals(0, failing(second, "mesh"));

            instruments.close();
            assertTrue(reader.collectAllMetrics().stream().noneMatch(m ->
                    m.getName().startsWith("seclume.certificate")
                            && !m.getData().getPoints().isEmpty()),
                    "still observed after close");
        }
    }

    private static long failing(Collection<MetricData> metrics, String bundle) {
        for (LongPointData point : metric(metrics, "seclume.certificate.renewal.failing")
                .getLongGaugeData().getPoints()) {
            if (bundle.equals(point.getAttributes().get(BUNDLE))) {
                return point.getValue();
            }
        }
        throw new AssertionError("no point for " + bundle);
    }

    private static MetricData metric(Collection<MetricData> metrics, String name) {
        return metrics.stream().filter(m -> m.getName().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError("no " + name + " in " + metrics));
    }
}
