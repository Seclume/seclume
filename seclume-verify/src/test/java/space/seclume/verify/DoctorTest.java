package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;

import org.junit.jupiter.api.Test;
import space.seclume.Secured;
import space.seclume.ServerCapacity;

class DoctorTest {
    private static final String URL = "jdbc:seclume:postgresql://localhost/app?user=test&provider=file&path=unused";

    @Test
    void inlineSecretsAreRefusedWithoutEchoingThem() {
        for (String option : new String[] {"password", "pass-word", "%70assword", "PWD"}) {
            Report report = new Report();
            assertEquals(2, Doctor.run(URL + "&" + option + "=do-not-print-this", null, report));
            assertFalse(report.json(2).contains("do-not-print-this"));
            assertTrue(report.hasProblems());
        }
    }

    @Test
    void usageAndJsonKeepExitStatusConsistent() {
        for (String[] args : new String[][] {
                {"--doctor"}, {"--doctor", "--pool-size"},
                {"--doctor", URL, "--pool-size", "0"}, {"--doctor", "--print-pin", URL}}) {
            assertEquals(2, Doctor.mainRun(args, new PrintStream(new ByteArrayOutputStream()),
                    new PrintStream(new ByteArrayOutputStream())));
        }
        var output = new ByteArrayOutputStream();
        assertEquals(2, Doctor.mainRun(new String[] {"--doctor", "--json", "jdbc:unknown:secret"},
                new PrintStream(output), System.err));
        assertTrue(output.toString().contains("\"status\": 2"));
        assertFalse(output.toString().contains("jdbc:unknown:secret"));
    }

    @Test
    void nativeTlsWithVerificationIsAcceptedAndPoolShortfallIsActionable() throws Exception {
        Report report = inspect("TLSv1.3 / TLS_AES_256_GCM_SHA384 (seclume)", "&tls=verify-full", 4, 8);
        assertFalse(report.hasProblems(), report.toString());
        assertFalse(inspect("TLSv1.2 / TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (seclume)",
                "&tls=verify-full", 4, 8).hasProblems());
        Report shortfall = inspect("TLSv1.3 (seclume)", "&tls=verify-full", 9, 8);
        assertTrue(shortfall.hasProblems());
        assertTrue(shortfall.toString().contains("Reduce maximum-pool-size"));
    }

    @Test
    void jsseAndUnverifiedOrPlaintextConnectionsCannotLookProtected() throws Exception {
        for (String tls : new String[] {null, "TLSv1.3 / AES", "TLSv1.2 / AES"}) {
            assertTrue(inspect(tls, "&tls=verify-full", null, 8).hasProblems());
        }
        Report unchecked = inspect("TLSv1.3 (seclume)", "&tls=require", null, 8);
        assertTrue(unchecked.hasProblems());
        assertTrue(unchecked.toString().contains("tls=verify-full"));
        assertFalse(inspect("TLSv1.3 (seclume)", "&tls=require&tlsPin=public-pin", null, 8).hasProblems());
    }

    @Test
    void unknownCapacityAndMissingCertificateAreNotReportedAsPassed() throws Exception {
        Report report = inspect("TLSv1.3 (seclume)", "&tls=verify-full", 4, -1);
        assertTrue(report.toString().contains("UNKNOWN - capacity"));
        assertTrue(report.toString().contains("UNKNOWN - driver did not expose"));
    }

    private static Report inspect(String tls, String options, Integer pool, int free) throws Exception {
        Connection connection = (Connection) Proxy.newProxyInstance(DoctorTest.class.getClassLoader(),
                new Class<?>[] {Connection.class, Secured.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "tlsDescription" -> tls;
                    case "serverCertificate" -> null;
                    case "unwrap" -> (ServerCapacity) () -> new ServerCapacity.Capacity(free, 0);
                    default -> throw new SQLException("unexpected probe");
                });
        Report report = new Report();
        report.title("doctor");
        Doctor.inspect(connection, Doctor.settings(URL + options), pool, report);
        return report;
    }
}
