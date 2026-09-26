package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import org.junit.jupiter.api.Test;

/**
 * {@code tlsRootCert=aws-rds}: Amazon RDS's global CA bundle ships with the
 * library, so an RDS connection can be verified without downloading it or
 * touching the JVM's trust store.
 */
class AwsRdsBundleTest {

    @Test
    void theBundleIsEveryRegionsCa() throws Exception {
        KeyStore store = TrustChoice.store("aws-rds");
        int count = 0;
        int valid = 0;
        Date now = new Date();
        for (String alias : Collections.list(store.aliases())) {
            X509Certificate certificate = (X509Certificate) store.getCertificate(alias);
            count++;
            assertTrue(certificate.getBasicConstraints() >= 0,
                    "not a CA: " + certificate.getSubjectX500Principal());
            assertTrue(certificate.getSubjectX500Principal().getName().contains("Amazon"),
                    certificate.getSubjectX500Principal().getName());
            if (!now.before(certificate.getNotBefore()) && !now.after(certificate.getNotAfter())) {
                valid++;
            }
        }
        // 108 of RDS's own bundle (25.09.2026) and the four Amazon Trust Services
        // roots (26.09.2026): an Aurora express cluster's relay and RDS Proxy
        // present certificates from those, and the bundle refused them.
        assertEquals(112, count, "108 RDS CAs and four Amazon roots");
        assertTrue(valid > 100, "only " + valid + " of " + count + " are valid today - the "
                + "bundle wants refreshing from truststore.pki.rds.amazonaws.com");
    }

    @Test
    void aNameThatIsNeitherABundleNorAFileIsRefused() {
        assertThrows(java.io.IOException.class, () -> TrustChoice.store("aws-rds-typo"));
    }
}
