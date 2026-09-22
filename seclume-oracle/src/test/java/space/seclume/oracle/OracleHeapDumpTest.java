package space.seclume.oracle;

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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.tck.ChildJvm;
import space.seclume.tck.HeapDumpScanner;
import space.seclume.tck.TestHosts;

/**
 * The proof for the Oracle driver - the fourth and last one to get it.
 *
 * <p>A JVM of its own logs in six times, does work, keeps one connection open
 * and writes out its heap. The password must not be in it, in any encoding.
 *
 * <p><b>Oracle handles the password more than the other three do.</b>
 * PostgreSQL runs SASL over it, MySQL hashes it into one packet, SQL Server
 * obfuscates it - Oracle derives a key from it, decrypts the server's
 * challenge with that key and sends an encrypted answer back. More steps mean
 * more places where a {@code String} or a {@code byte[]} would be the
 * convenient thing to reach for, and any one of them would leave the password
 * on the heap for as long as the garbage collector felt like it.
 *
 * <p>The control matters as much as the assertion: a marker value comes back
 * from the server through the same connection and <b>has</b> to be in the
 * dump. Without it an empty result would prove only that the scanner was
 * looking into the void.
 *
 * <p>Both encodings are searched. The password reaches the protocol as UTF-8,
 * but a {@code String} on the heap is UTF-16 - so a driver that built one
 * would be missed by a scan that only knew the wire encoding. That is what
 * {@code HeapDumpScanner.scan} does, and it is why this asks it rather than
 * comparing bytes itself.
 */
@Timeout(300)
class OracleHeapDumpTest {

    @TempDir
    Path directory;

    /** A value that arrives as a column and is meant to be on the heap. */
    private static final String MARKER = "Nutzdaten-Marker-ORA-9e21bd";

    private String host;
    private int port;
    private String service;
    private String user;
    private Path password;

    @BeforeEach
    void findTheServer() {
        host = System.getProperty("seclume.oracle.host", TestHosts.database());
        Assumptions.assumeTrue(host != null, "no Oracle host configured");
        port = Integer.getInteger("seclume.oracle.port", 1521);
        service = System.getProperty("seclume.oracle.service", "FREEPDB1");
        user = System.getProperty("seclume.oracle.user", "seclume_test");
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no Oracle on " + host + ":" + port);
        }
    }

    @Test
    void aLoginLeavesNothingInTheHeap() throws Exception {
        String secret = Files.readString(password, StandardCharsets.UTF_8).strip();
        Assumptions.assumeTrue(secret.length() >= 8, "the password is too short to search for");
        Path dump = directory.resolve("oracle.hprof");

        ChildJvm.Result result = ChildJvm.run(OraProbe.class,
                List.of(password.toString(), dump.toString(), host, String.valueOf(port),
                        service, user, MARKER, "5"), 240);
        assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
        assertTrue(result.output().contains("connected 6 times"),
                "the probe did not log in as expected:\n" + result.output());
        assertTrue(result.output().contains("marker seen 5 times"),
                "the probe did not read the marker back:\n" + result.output());

        // The control: the marker came over the same connection and is on the
        // heap, so the scanner works and the dump is the right one.
        assertFalse(HeapDumpScanner.scan(dump, MARKER).isEmpty(),
                "the marker is not in the dump - then the scan proves nothing");

        List<HeapDumpScanner.Finding> findings = HeapDumpScanner.scan(dump, secret);
        assertTrue(findings.isEmpty(), "the database password is in the heap dump:\n"
                + findings.stream().map(Object::toString).reduce("", (a, b) -> a + "\n" + b));
    }
}
