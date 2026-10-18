package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.tck.ChildJvm;
import space.seclume.tck.HeapDumpScanner;
import space.seclume.tck.TestHosts;

/**
 * Verifies that an active APM Java Agent (specifically OpenTelemetry) does not
 * capture or retain database credentials on the heap.
 *
 * <p>APM agents routinely attach to Java applications and bytecode-instrument
 * JDBC calls (such as {@code DriverManager.getConnection}, {@code prepareStatement},
 * and connection pools) to generate distributed traces. If a driver handles
 * credentials as Java heap objects (such as {@code String} passwords or tokens),
 * the agent's interceptors, arguments capture, or error handlers could retain
 * those secrets in memory or logs.
 *
 * <p>seclume writes credentials directly from off-heap native memory into the
 * network stream, bypassing Java APIs where an agent could observe them. This test
 * runs a child JVM with the official OpenTelemetry Java agent attached, enables
 * JDBC instrumentation and logging span export, verifies that PostgreSQL spans
 * were actually produced, and confirms that a full heap dump contains no trace of
 * the database password.
 */
@org.junit.jupiter.api.parallel.Isolated
class ApmAgentHeapDumpTest {

    @TempDir
    Path directory;

    private static Path passwordFile;
    private static Path agentJar;

    @BeforeAll
    static void checkPrerequisites() {
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(passwordFile != null, TestHosts.postgresPasswordFile() + " is not there");

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    TestHosts.postgres(), TestHosts.postgresPort()), 1000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on "
                    + TestHosts.postgres() + ":" + TestHosts.postgresPort());
        }

        agentJar = findAgentJar();
        Assumptions.assumeTrue(agentJar != null,
                "opentelemetry-javaagent jar was not found on classpath or in ~/.m2");
    }

    private static Path findAgentJar() {
        String classPath = System.getProperty("java.class.path");
        if (classPath != null) {
            for (String entry : classPath.split(File.pathSeparator)) {
                if (entry.contains("opentelemetry-javaagent") && entry.endsWith(".jar")
                        && !entry.endsWith("-sources.jar") && !entry.endsWith("-javadoc.jar")) {
                    Path p = Path.of(entry);
                    if (Files.isRegularFile(p)) {
                        return p.toAbsolutePath().normalize();
                    }
                }
            }
        }
        Path m2Dir = Path.of(System.getProperty("user.home"), ".m2", "repository", "io",
                "opentelemetry", "javaagent", "opentelemetry-javaagent");
        if (Files.isDirectory(m2Dir)) {
            try (Stream<Path> stream = Files.walk(m2Dir)) {
                for (Path p : stream.filter(Files::isRegularFile).toList()) {
                    String name = p.getFileName().toString();
                    if (name.startsWith("opentelemetry-javaagent-") && name.endsWith(".jar")
                            && !name.endsWith("-sources.jar") && !name.endsWith("-javadoc.jar")) {
                        return p.toAbsolutePath().normalize();
                    }
                }
            } catch (IOException ignored) {
            }
        }
        return null;
    }

    @Test
    void apmAgentDoesNotLeakPasswordToHeapDump() throws Exception {
        Path dump = directory.resolve("apm-agent.hprof");
        String url = "jdbc:seclume:postgresql://" + TestHosts.postgres()
                + ":" + TestHosts.postgresPort() + "/seclume_test"
                + "?user=seclume_test&provider=file&path="
                + passwordFile.toString().replace('\\', '/');

        List<String> jvmArguments = List.of(
                "-javaagent:" + agentJar.toString().replace('\\', '/'),
                "-Dotel.traces.exporter=logging",
                "-Dotel.metrics.exporter=none",
                "-Dotel.logs.exporter=none",
                "-Dotel.instrumentation.jdbc.enabled=true"
        );

        ChildJvm.Result result = ChildJvm.run(JdbcProbe.class, jvmArguments,
                List.of(url, dump.toString(), "5"), 180);

        assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
        assertTrue(result.output().contains("connected 6 times via JDBC"),
                "the probe did not do its work:\n" + result.output());

        // Prove the agent was active: the logging exporter must have emitted spans from the JDBC instrumentation
        boolean hasJdbcSpan = result.output().contains("LoggingSpanExporter")
                && (result.output().contains("db.system=postgresql") || result.output().contains("db.system=other_sql"))
                && result.output().contains("db.statement=select");
        assertTrue(hasJdbcSpan,
                "the OpenTelemetry agent did not log JDBC spans:\n" + result.output());

        // Scan heap dump for the secret
        String secret = Files.readString(passwordFile, StandardCharsets.UTF_8).strip();
        List<HeapDumpScanner.Finding> findings = HeapDumpScanner.scan(dump, secret);
        assertTrue(findings.isEmpty(),
                "the database password was found in the heap dump:\n"
                + findings.stream().map(Object::toString).reduce("", (a, b) -> a + "\n" + b));
    }
}
