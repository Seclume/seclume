package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.mysql.FakeMySqlServer.Column;
import space.seclume.tck.ChildJvm;
import space.seclume.tck.HeapDumpScanner;

/**
 * The proof for the MySQL driver.
 *
 * <p>A JVM of its own logs in six times, does work, keeps one connection open
 * and writes out its heap. The password must not appear in it - neither raw nor
 * inside an array, neither as UTF-8 nor as UTF-16.
 *
 * <p>A complete {@code mysql_native_password} handshake runs through that
 * procedure: three SHA-1 computations over the password and one XOR. If one of
 * those steps went across the heap - because somebody used
 * {@code String.getBytes}, say - the password would stand in the dump, and
 * still would minutes later.
 *
 * <p>The server is the test server inside this process. For the question being
 * checked here that does not matter: the dump comes from the <b>other</b>
 * process, and that is where the real driver code runs.
 */
class MyHeapDumpTest {

    @TempDir
    Path directory;

    private static final String PASSWORD = "Heapdump-Testpasswort-7f3a9c2e";
    /**
     * A value that comes over the same connection and <b>is meant</b> to end
     * up on the heap: the probe collects it in a list. It is the control - if
     * the scanner does not find it, it is searching in the void, and the empty
     * result for the password would be worthless.
     */
    private static final String MARKER = "Nutzdaten-Marker-3b91ce7a";

    @Test
    void aHandshakeLeavesNothingInTheHeap() throws Exception {
        Path secretFile = directory.resolve("password");
        Files.writeString(secretFile, PASSWORD, StandardCharsets.UTF_8);
        Path dump = directory.resolve("mysql.hprof");

        try (FakeMySqlServer server = new FakeMySqlServer("seclume_test", PASSWORD)) {
            server.answerWith(
                    List.of(new Column("id", MyTypes.LONGLONG), new Column("label", MyTypes.VAR_STRING)),
                    List.of(List.of("1", MARKER), List.of("2", "zwei")));
            server.start();

            ChildJvm.Result result = ChildJvm.run(MyProbe.class,
                    List.of(secretFile.toAbsolutePath().toString(), dump.toString(),
                            String.valueOf(server.port()), "5"), 180);
            assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
            assertTrue(result.output().contains("plugin=mysql_native_password"),
                    "the probe did not authenticate as expected:\n" + result.output());
            server.rethrowFailure();
        }

        List<HeapDumpScanner.Finding> findings = HeapDumpScanner.scan(dump, PASSWORD);
        assertTrue(findings.isEmpty(),
                "the database password is in the heap dump:\n"
                + findings.stream().map(Object::toString).reduce("", (a, b) -> a + "\n" + b));
    }
}
