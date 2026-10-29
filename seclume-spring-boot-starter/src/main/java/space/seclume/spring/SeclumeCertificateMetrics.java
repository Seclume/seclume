package space.seclume.spring;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.binder.MeterBinder;

import space.seclume.keys.ManagedCertificate;

/**
 * Meters for the SSL bundles whose certificate seclume-keys keeps current, so
 * that an alert can fire before a certificate ends - not when it has:
 *
 * <ul>
 *   <li>{@code seclume.certificate.expiry} - seconds until the certificate in
 *       use ends;
 *   <li>{@code seclume.certificate.renewal.failing} - 1 while its last renewal
 *       failed, 0 otherwise.
 * </ul>
 *
 * Tagged {@code bundle}. Each value is looked up when it is read, so a
 * certificate renewed meanwhile counts; one not (yet) there reads NaN.
 */
public final class SeclumeCertificateMetrics implements MeterBinder {

    private final Map<String, String> names;

    /** @param names bundle name to the name {@code SeclumeKeys.managedCertificates()} uses */
    public SeclumeCertificateMetrics(Map<String, String> names) {
        this.names = Map.copyOf(names);
    }

    @Override
    public void bindTo(MeterRegistry registry) {
        names.forEach((bundle, name) -> {
            Tags tags = Tags.of("bundle", bundle);
            Gauge.builder("seclume.certificate.expiry", name, SeclumeCertificateMetrics::expiry)
                    .description("seconds until the certificate in use ends")
                    .baseUnit("seconds").tags(tags).register(registry);
            Gauge.builder("seclume.certificate.renewal.failing", name,
                            SeclumeCertificateMetrics::failing)
                    .description("1 while the last renewal of the certificate failed")
                    .tags(tags).register(registry);
        });
    }

    static double expiry(String name) {
        ManagedCertificate certificate = KeyCertificates.named(name);
        return certificate == null ? Double.NaN
                : Duration.between(Instant.now(), certificate.notAfter()).toSeconds();
    }

    static double failing(String name) {
        ManagedCertificate certificate = KeyCertificates.named(name);
        return certificate == null ? Double.NaN : certificate.lastFailure() == null ? 0 : 1;
    }
}
