package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.pool.PoolStatistics;

/** Each finding at its level, and the grade the worst of them. */
class SeclumeAssessmentTest {

    private static final Instant NOW = Instant.parse("2026-10-13T12:00:00Z");
    private static final String TLS13 = "TLSv1.3 TLS_AES_256_GCM_SHA384 (seclume)";

    private static PoolStatistics quiet() {
        return new PoolStatistics("p", 2, 1, 1, 0, 10, 2, 0, 0, 0, 0, 0);
    }

    @Test
    void aWellSecuredQuietPoolIsOk() {
        SeclumeAssessment assessment = SeclumeAssessment.of("scram-sha-256-plus", TLS13,
                NOW.plus(Duration.ofDays(200)), quiet(), 10, 0, NOW);
        assertEquals(SeclumeAssessment.Level.OK, assessment.grade());
        assertTrue(assessment.findings().isEmpty());
    }

    @Test
    void noTlsIsCritical() {
        SeclumeAssessment assessment = SeclumeAssessment.of("scram-sha-256", null, null,
                quiet(), 10, 0, NOW);
        assertEquals(SeclumeAssessment.Level.CRITICAL, assessment.grade());
    }

    @Test
    void theCertificateIsGradedByTheTimeLeft() {
        assertEquals(SeclumeAssessment.Level.CRITICAL, grade(NOW.minus(Duration.ofDays(1))),
                "expired");
        assertEquals(SeclumeAssessment.Level.CRITICAL, grade(NOW.plus(Duration.ofDays(5))));
        assertEquals(SeclumeAssessment.Level.WARNING, grade(NOW.plus(Duration.ofDays(20))));
        assertEquals(SeclumeAssessment.Level.OK, grade(NOW.plus(Duration.ofDays(31))));
    }

    private static SeclumeAssessment.Level grade(Instant expires) {
        return SeclumeAssessment.of("scram-sha-256", TLS13, expires, quiet(), 10, 0, NOW)
                .grade();
    }

    @Test
    void weakLoginsWarnAndTls12IsANote() {
        for (String weak : List.of("md5", "password", "trust", "mysql_native_password")) {
            assertEquals(SeclumeAssessment.Level.WARNING, SeclumeAssessment.of(weak, TLS13,
                    null, quiet(), 10, 0, NOW).grade(), weak);
        }
        assertEquals(SeclumeAssessment.Level.NOTE, SeclumeAssessment.of("scram-sha-256",
                "TLSv1.2 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (seclume)", null, quiet(), 10,
                0, NOW).grade());
    }

    @Test
    void aStrugglingPoolWarnsAndTheWorstFindingComesFirst() {
        PoolStatistics saturated = new PoolStatistics("p", 4, 4, 0, 3, 100, 4, 0, 7, 1, 0, 0);
        SeclumeAssessment assessment = SeclumeAssessment.of("md5", null, null, saturated, 4,
                2, NOW);
        assertEquals(SeclumeAssessment.Level.CRITICAL, assessment.grade());
        assertEquals(SeclumeAssessment.Level.CRITICAL, assessment.findings().get(0).level());
        long poolWarnings = assessment.findings().stream()
                .filter(f -> f.check().equals("pool")).count();
        assertEquals(4, poolWarnings, "timeouts, saturation, leaks, refused resets");
        Map<String, Object> shown = assessment.asMap();
        assertEquals("critical", shown.get("grade"));
    }

    /** A certificate that renews itself is judged by its own lifetime, not in days. */
    @Test
    void aSelfRenewingCertificateIsJudgedByItsOwnLife() {
        Instant start = NOW.minus(Duration.ofHours(10));
        Instant end = start.plus(Duration.ofHours(24));
        Instant renewal = start.plus(Duration.ofHours(16));
        assertEquals(SeclumeAssessment.Level.OK,
                SeclumeAssessment.ofCertificate(start, end, renewal, null, null, NOW).grade(),
                "a 24-hour certificate is not critical for expiring within a week");
        SeclumeAssessment overdue = SeclumeAssessment.ofCertificate(start, end, renewal, null,
                null, start.plus(Duration.ofHours(18)));
        assertEquals(SeclumeAssessment.Level.WARNING, overdue.grade());
        assertTrue(overdue.findings().get(0).detail().contains("was due"),
                overdue.findings().toString());
        SeclumeAssessment failing = SeclumeAssessment.ofCertificate(start, end, renewal,
                "Vault answered 503", start.plus(Duration.ofHours(16)),
                start.plus(Duration.ofHours(17)));
        assertEquals(SeclumeAssessment.Level.WARNING, failing.grade());
        assertTrue(failing.findings().get(0).detail().contains("503")
                && failing.findings().get(0).detail().contains("7 hours"),
                failing.findings().toString());
        assertEquals(SeclumeAssessment.Level.CRITICAL, SeclumeAssessment.ofCertificate(start,
                end, renewal, "Vault answered 503", start.plus(Duration.ofHours(16)),
                start.plus(Duration.ofHours(22))).grade(), "a tenth of its life left, failing");
        assertEquals(SeclumeAssessment.Level.CRITICAL, SeclumeAssessment.ofCertificate(start,
                end, renewal, null, null, end.plusSeconds(60)).grade());
    }

    /** One renewed on disk by somebody else is judged in days, like a server's. */
    @Test
    void aCertificateOnDiskIsJudgedInDays() {
        Instant start = NOW.minus(Duration.ofDays(300));
        assertEquals(SeclumeAssessment.Level.CRITICAL, SeclumeAssessment.ofCertificate(start,
                NOW.plus(Duration.ofDays(5)), null, null, null, NOW).grade());
        assertEquals(SeclumeAssessment.Level.WARNING, SeclumeAssessment.ofCertificate(start,
                NOW.plus(Duration.ofDays(20)), null, null, null, NOW).grade());
        assertEquals(SeclumeAssessment.Level.OK, SeclumeAssessment.ofCertificate(start,
                NOW.plus(Duration.ofDays(100)), null, null, null, NOW).grade());
        SeclumeAssessment refused = SeclumeAssessment.ofCertificate(start,
                NOW.plus(Duration.ofDays(100)), null, "the certificate is not the key's",
                NOW.minus(Duration.ofMinutes(5)), NOW);
        assertEquals(SeclumeAssessment.Level.WARNING, refused.grade());
        assertTrue(refused.findings().get(0).detail().contains("refused"));
    }
}
