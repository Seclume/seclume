package space.seclume.spring;

import java.util.Map;

import io.opentelemetry.api.OpenTelemetry;

import space.seclume.keys.ManagedCertificate;
import space.seclume.opentelemetry.SeclumeCertificateInstruments;

/**
 * The certificates of the SSL bundles that seclume-keys keeps current, as
 * OpenTelemetry gauges - {@code seclume.certificate.expiry} and
 * {@code seclume.certificate.renewal.failing}, attributed {@code bundle} - for
 * an application that exports with OpenTelemetry rather than Micrometer.
 * Started with {@code seclume.metrics.opentelemetry=true}; closed with the
 * context.
 */
public final class SeclumeCertificateOpenTelemetry implements AutoCloseable {

    private final AutoCloseable instruments;

    /** @param names bundle name to the name {@code SeclumeKeys.managedCertificates()} uses */
    SeclumeCertificateOpenTelemetry(OpenTelemetry openTelemetry, Map<String, String> names) {
        this.instruments = SeclumeCertificateInstruments.observe(openTelemetry, names, name -> {
            ManagedCertificate certificate = KeyCertificates.named(name);
            return certificate == null ? null : new SeclumeCertificateInstruments.Reading(
                    certificate.notAfter(), certificate.lastFailure() != null);
        });
    }

    @Override
    public void close() {
        try {
            instruments.close();
        } catch (Exception e) {
            throw new IllegalStateException("the certificate gauges could not be closed", e);
        }
    }
}
