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
}
