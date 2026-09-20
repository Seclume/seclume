package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import space.seclume.tck.TestHosts;

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

/**
 * The proof for the PostgreSQL driver: a JVM of its own logs in to a real
 * server several times, keeps one connection open and writes out its heap. The
 * password must not appear in it - neither raw nor inside an array.
 *
 * <p>Unlike the core proof, a complete SCRAM handshake runs through the code
 * here: PBKDF2 over the password, client key, stored key, proof. If any step of
 * that runs across the heap, it shows up here.
 */
class PgHeapDumpTest {

    @TempDir
    Path directory;

    private static Path passwordFile;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate;
            }
        }
        Assumptions.assumeTrue(passwordFile != null, TestHosts.postgresPasswordFile() + " is not there");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(TestHosts.postgres(), TestHosts.postgresPort()), 1000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + TestHosts.postgres() + ":" + TestHosts.postgresPort());
        }
    }

    @Test
    void aRealHandshakeLeavesNothingInTheHeap() throws Exception {
        Path dump = directory.resolve("postgres.hprof");
        ChildJvm.Result result = ChildJvm.run(PgProbe.class,
                List.of(passwordFile.toAbsolutePath().toString(), dump.toString(), "5"), 180);
        assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
        assertTrue(result.output().contains("auth=scram-sha-256"),
                "the probe did not authenticate with SCRAM:\n" + result.output());

        // The test knows the password because it searches for it - the dump
        // comes from another JVM, so that falsifies nothing.
        String secret = Files.readString(passwordFile, StandardCharsets.UTF_8).strip();
        List<HeapDumpScanner.Finding> findings = HeapDumpScanner.scan(dump, secret);
        assertTrue(findings.isEmpty(),
                "the database password is in the heap dump:\n"
                + findings.stream().map(Object::toString).reduce("", (a, b) -> a + "\n" + b));
    }
}
