package space.seclume.jasper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.tck.ChildJvm;
import space.seclume.tck.HeapDumpScanner;
import space.seclume.tck.TestHosts;

/**
 * Secret provider -> seclume native memory -> seclume JDBC -> JasperReports,
 * embedded: after three reports are filled and with the pool still open, the
 * database password is not on the heap. And a negative control that makes
 * the usual mistake, and must be caught - otherwise finding nothing would
 * prove nothing.
 */
class JasperReportsHeapTest {

    @TempDir
    Path directory;

    private static Path passwordFile;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(passwordFile != null,
                TestHosts.postgresPasswordFile() + " is not there");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    TestHosts.postgres(), TestHosts.postgresPort()), 1000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on "
                    + TestHosts.postgres() + ":" + TestHosts.postgresPort());
        }
    }

    private List<HeapDumpScanner.Finding> run(String mode) throws Exception {
        Path dump = directory.resolve(mode + ".hprof");
        ChildJvm.Result result = ChildJvm.run(JasperProbe.class, List.of(mode,
                TestHosts.postgres(), String.valueOf(TestHosts.postgresPort()),
                passwordFile.toString(), dump.toString()), 240);
        assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
        assertTrue(result.output().contains("filled 3 reports of 50 rows over seclume"),
                "the probe did not do its work:\n" + result.output());
        // The parent reads the password to search for it - in this process,
        // not in the one whose heap was dumped.
        String secret = Files.readString(passwordFile, StandardCharsets.UTF_8).strip();
        return HeapDumpScanner.scan(dump, secret);
    }

    @Test
    void aReportFilledOverSeclumeLeavesNoPasswordInTheHeap() throws Exception {
        List<HeapDumpScanner.Finding> findings = run("clean");
        assertTrue(findings.isEmpty(), "the database password is in the heap dump:\n"
                + findings.stream().map(Object::toString).reduce("", (a, b) -> a + "\n" + b));
    }

    @Test
    void theNegativeControlIsCaught() throws Exception {
        assertFalse(run("leaking").isEmpty(),
                "the password was put on the heap on purpose and the search missed it - "
                + "then an empty result above proves nothing");
    }
}
