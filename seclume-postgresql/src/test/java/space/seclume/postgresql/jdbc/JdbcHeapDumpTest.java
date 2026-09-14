package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

/**
 * The same proof as in {@code PgHeapDumpTest}, but through the JDBC surface -
 * that is, along the path an application really takes.
 *
 * <p>The difference is not cosmetic: here the URL runs through
 * {@code SeclumeUrl}, through {@code SecretProviders} and through the
 * {@code DriverManager}, and every one of those places would have the
 * opportunity to lift the password into a {@code String}.
 */
class JdbcHeapDumpTest {

    @TempDir
    Path directory;

    private static Path passwordFile;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(".local-pg-password"),
                Path.of("..", ".local-pg-password"))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(passwordFile != null, "no .local-pg-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", 5432), 1000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on 127.0.0.1:5432");
        }
    }

    @Test
    void theJdbcPathLeavesNothingInTheHeap() throws Exception {
        Path dump = directory.resolve("jdbc.hprof");
        String url = "jdbc:seclume:postgresql://127.0.0.1:5432/seclume_test"
                + "?user=seclume_test&provider=file&path="
                + passwordFile.toString().replace('\\', '/');

        ChildJvm.Result result = ChildJvm.run(JdbcProbe.class,
                List.of(url, dump.toString(), "5"), 180);
        assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
        assertTrue(result.output().contains("connected 6 times via JDBC"),
                "the probe did not do its work:\n" + result.output());

        String secret = Files.readString(passwordFile, StandardCharsets.UTF_8).strip();
        List<HeapDumpScanner.Finding> findings = HeapDumpScanner.scan(dump, secret);
        assertTrue(findings.isEmpty(),
                "the database password is in the heap dump:\n"
                + findings.stream().map(Object::toString).reduce("", (a, b) -> a + "\n" + b));
    }
}
