package space.seclume.opentelemetry;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.metrics.Meter;

/**
 * Certificates that renew themselves - from Vault's PKI, SPIFFE, a pair
 * reloaded from disk - as two gauges, so that an alert can fire before one
 * ends rather than when it has: the OpenTelemetry counterpart of the
 * Micrometer meters of the same names.
 *
 * <ul>
 *   <li>{@code seclume.certificate.expiry} ({@code s}) - seconds until the
 *       certificate in use ends;
 *   <li>{@code seclume.certificate.renewal.failing} - 1 while its last renewal
 *       failed, 0 otherwise.
 * </ul>
 *
 * <p>Attributed {@code bundle}. Each value is read when the SDK collects -
 * through {@code read}, by the name the certificate is listed under - so a
 * certificate renewed meanwhile counts, and one not there (yet) is left out
 * of that collection rather than reported as a number it does not have.
 *
 * <pre>
 *   AutoCloseable instruments = SeclumeCertificateInstruments.observe(otel,
 *           Map.of("web", "orders.svc"), name -&gt; ...);
 * </pre>
 */
public final class SeclumeCertificateInstruments {

    /** What is known of one certificate when the SDK collects. */
    public record Reading(Instant notAfter, boolean renewalFailing) {
    }

    private static final AttributeKey<String> BUNDLE = AttributeKey.stringKey("bundle");

    private SeclumeCertificateInstruments() {
    }

    /**
     * Observes the certificates in {@code names} - bundle name to the name the
     * certificate is listed under - until the returned handle is closed.
     *
     * @param read the certificate's reading by its listed name, or {@code null}
     *             when there is none
     */
    public static AutoCloseable observe(OpenTelemetry openTelemetry, Map<String, String> names,
            Function<String, Reading> read) {
        Map<String, String> observed = Map.copyOf(names);
        Meter meter = SeclumeMetrics.meter(openTelemetry);
        List<AutoCloseable> observations = List.of(
                meter.gaugeBuilder("seclume.certificate.expiry")
                        .setUnit("s")
                        .setDescription("seconds until the certificate in use ends")
                        .buildWithCallback(measurement -> observed.forEach((bundle, name) -> {
                            Reading reading = read.apply(name);
                            if (reading != null) {
                                measurement.record(Duration.between(Instant.now(),
                                        reading.notAfter()).toMillis() / 1000.0,
                                        Attributes.of(BUNDLE, bundle));
                            }
                        })),
                meter.gaugeBuilder("seclume.certificate.renewal.failing")
                        .ofLongs()
                        .setDescription("1 while the last renewal of the certificate failed")
                        .buildWithCallback(measurement -> observed.forEach((bundle, name) -> {
                            Reading reading = read.apply(name);
                            if (reading != null) {
                                measurement.record(reading.renewalFailing() ? 1 : 0,
                                        Attributes.of(BUNDLE, bundle));
                            }
                        })));
        return () -> {
            for (AutoCloseable observation : observations) {
                observation.close();
            }
        };
    }
}
