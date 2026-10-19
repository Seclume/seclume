package space.seclume.mongodb.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.tck.ChildJvm;
import space.seclume.tck.HeapDumpScanner;

/**
 * The OpenTelemetry Java agent in the process, its MongoDB instrumentation
 * on: it registers a command listener with the official driver and records
 * every command it sees. The login is seclume's - on the socket, below the
 * driver, from native memory - so neither the agent nor anything it keeps
 * holds the password. The child JVM's spans prove the agent was at work,
 * and its heap dump is searched for the password.
 *
 * <p>Against the standalone of the {@code mongo_fixtures.sh} fixture;
 * skipped without it. {@code -Dseclume.mongo.control=true} runs the control:
 * the official driver given the password itself, under the same agent - and
 * the same search finds it.
 */
@org.junit.jupiter.api.parallel.Isolated
class ApmAgentHeapDumpTest {

    @TempDir
    Path directory;

    private static String host;
    private static Path password;
    private static Path ca;
    private static Path agent;

    @BeforeAll
    static void needsTheStandaloneAndTheAgent() {
        host = System.getProperty("seclume.mongo.host", space.seclume.tck.TestHosts.database());
        password = find(".local-mongo-password");
        ca = find(".local-mongo-ca.pem");
        assumeTrue(password != null && ca != null, "no MongoDB fixture files");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, 27017), 2000);
        } catch (IOException e) {
            assumeTrue(false, "no MongoDB on " + host + ":27017");
        }
        agent = agentJar();
        assumeTrue(agent != null, "the opentelemetry-javaagent jar is not in ~/.m2");
    }

    private static Path find(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static Path agentJar() {
        Path versions = Path.of(System.getProperty("user.home"), ".m2", "repository", "io",
                "opentelemetry", "javaagent", "opentelemetry-javaagent");
        if (!Files.isDirectory(versions)) {
            return null;
        }
        try (Stream<Path> files = Files.walk(versions)) {
            return files.filter(p -> p.getFileName().toString().matches(
                    "opentelemetry-javaagent-[0-9.]+\\.jar")).findFirst()
                    .map(p -> p.toAbsolutePath().normalize()).orElse(null);
        } catch (IOException e) {
            return null;
        }
    }

    @Test
    void controlTheVendorsOwnLoginLeavesThePasswordOnTheHeap() throws Exception {
        assumeTrue(Boolean.getBoolean("seclume.mongo.control"), "-Dseclume.mongo.control=true");
        Path dump = directory.resolve("mongo-apm-control.hprof");
        ChildJvm.Result result = ChildJvm.run(MongoAgentProbe.class, List.of(
                "-javaagent:" + agent.toString().replace('\\', '/'),
                "-Dotel.traces.exporter=logging", "-Dotel.metrics.exporter=none",
                "-Dotel.logs.exporter=none"),
                List.of("unused", dump.toString(), "control", host, password.toString(),
                        ca.toString()), 180);
        assertEquals(0, result.exitCode(), "the control failed:\n" + result.output());
        String secret = Files.readString(password, StandardCharsets.UTF_8).strip();
        assertTrue(!HeapDumpScanner.scan(dump, secret).isEmpty(),
                "the control found no password - the search would prove nothing");
    }

    @Test
    void theAgentSeesTheCommandsAndNeverThePassword() throws Exception {
        Path dump = directory.resolve("mongo-apm-agent.hprof");
        String url = "mongodb://seclume_test@" + host + ":27017/?authSource=admin"
                + "&provider=file&path=" + password.toString().replace('\\', '/')
                + "&tlsRootCert=" + ca.toString().replace('\\', '/');
        ChildJvm.Result result = ChildJvm.run(MongoAgentProbe.class, List.of(
                "-javaagent:" + agent.toString().replace('\\', '/'),
                "-Dotel.traces.exporter=logging",
                "-Dotel.metrics.exporter=none",
                "-Dotel.logs.exporter=none",
                "-Dotel.instrumentation.mongo.enabled=true"),
                List.of(url, dump.toString()), 180);

        assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
        assertTrue(result.output().contains("both clients wrote and read, 10 reads"),
                "the probe did not do its work:\n" + result.output());
        // The agent was at work: the official driver's commands are spans.
        assertTrue(result.output().contains("LoggingSpanExporter")
                        && result.output().contains("mongodb"),
                "the OpenTelemetry agent logged no MongoDB spans:\n" + result.output());

        String secret = Files.readString(password, StandardCharsets.UTF_8).strip();
        List<HeapDumpScanner.Finding> findings = HeapDumpScanner.scan(dump, secret);
        assertTrue(findings.isEmpty(), "the password is in the heap dump:\n"
                + findings.stream().map(Object::toString).reduce("", (a, b) -> a + "\n" + b));
    }
}
