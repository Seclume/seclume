package space.seclume.spring;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import space.seclume.keys.ManagedCertificate;
import space.seclume.keys.SeclumeKeys;

/**
 * The application's own certificates that seclume-keys keeps current, for the
 * endpoint - kept apart so that nothing else touches seclume-keys' classes
 * when it is not on the class path.
 */
final class KeyCertificates {

    static final boolean PRESENT = present();

    private KeyCertificates() {
    }

    private static boolean present() {
        try {
            Class.forName("space.seclume.keys.SeclumeKeys", false,
                    KeyCertificates.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException | LinkageError absent) {
            return false;
        }
    }

    /** Each certificate: its validity, when it renews, why it last failed to, and a grade. */
    static List<Map<String, Object>> describe(Instant now) {
        return SeclumeKeys.managedCertificates().stream().map(c -> describe(c, now)).toList();
    }

    private static Map<String, Object> describe(ManagedCertificate certificate, Instant now) {
        Map<String, Object> shown = new LinkedHashMap<>();
        shown.put("name", certificate.name());
        shown.put("kind", certificate.kind());
        shown.put("subject", certificate.subject());
        shown.put("notBefore", certificate.notBefore().toString());
        shown.put("expires", certificate.notAfter().toString());
        if (certificate.nextRenewal() != null) {
            shown.put("nextRenewal", certificate.nextRenewal().toString());
        }
        shown.put("generations", certificate.generations());
        if (certificate.lastFailure() != null) {
            Map<String, Object> failure = new LinkedHashMap<>();
            failure.put("at", String.valueOf(certificate.failedAt()));
            failure.put("reason", certificate.lastFailure());
            shown.put("lastFailure", failure);
        }
        shown.put("assessment", SeclumeAssessment.ofCertificate(certificate.notBefore(),
                certificate.notAfter(), certificate.nextRenewal(), certificate.lastFailure(),
                certificate.failedAt(), now).asMap());
        return shown;
    }

    /** One certificate by name, or {@code null} - for a meter that asks again each time. */
    static ManagedCertificate named(String name) {
        for (ManagedCertificate certificate : SeclumeKeys.managedCertificates()) {
            if (certificate.name().equals(name)) {
                return certificate;
            }
        }
        return null;
    }
}
