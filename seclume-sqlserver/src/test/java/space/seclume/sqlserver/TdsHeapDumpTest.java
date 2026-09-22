package space.seclume.sqlserver;

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
 * The proof for the SQL Server driver - which did not have one.
 *
 * <p>PostgreSQL and MySQL have had this since early on; SQL Server and Oracle
 * did not, so the central claim of this project was demonstrated for half of
 * it. A JVM of its own logs in six times, does work, keeps one connection open
 * and writes out its heap. The password must not be in it.
 *
 * <p><b>And not in its obfuscated form either, which is the part specific to
 * this protocol.</b> LOGIN7 re-encodes the password to UTF-16LE, swaps the
 * nibbles of every byte and XORs it with {@code 0xA5} - Microsoft calls that
 * obfuscation, and it is reversible without any key at all. A dump containing
 * those bytes is as good as a dump containing the password, so the scan looks
 * for both. A test that searched only for the plaintext would pass on a driver
 * that built the obfuscated form in a Java array and left it there.
 *
 * <p>The control matters as much as the assertion: a marker value comes back
 * from the server through the same connection and <b>has</b> to be in the
 * dump. Without it an empty result would prove only that the scanner was
 * looking into the void.
 */
@Timeout(300)
class TdsHeapDumpTest {

    @TempDir
    Path directory;

    /** A value that arrives as a column and is meant to be on the heap. */
    private static final String MARKER = "Nutzdaten-Marker-TDS-4c17ae";

    private String host;
    private int port;
    private Path password;

    @BeforeEach
    void findTheServer() {
        host = System.getProperty("seclume.mssql.host", TestHosts.database());
        Assumptions.assumeTrue(host != null, "no SQL Server host configured");
        port = Integer.getInteger("seclume.mssql.port", 1433);
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mssql-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no SQL Server on " + host + ":" + port);
        }
    }

    @Test
    void aLoginLeavesNeitherThePasswordNorItsObfuscationInTheHeap() throws Exception {
        String secret = Files.readString(password, StandardCharsets.UTF_8).strip();
        Assumptions.assumeTrue(secret.length() >= 8, "the password is too short to search for");
        Path dump = directory.resolve("sqlserver.hprof");

        ChildJvm.Result result = ChildJvm.run(TdsProbe.class,
                List.of(password.toString(), dump.toString(), host, String.valueOf(port),
                        MARKER, "5"), 240);
        assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
        assertTrue(result.output().contains("connected 6 times"),
                "the probe did not log in as expected:\n" + result.output());

        // The control: the marker came over the same connection and is on the
        // heap, so the scanner works and the dump is the right one.
        assertFalse(HeapDumpScanner.scan(dump, MARKER).isEmpty(),
                "the marker is not in the dump - then the scan proves nothing");

        List<HeapDumpScanner.Finding> plain = HeapDumpScanner.scan(dump, secret);
        assertTrue(plain.isEmpty(), "the database password is in the heap dump:\n"
                + plain.stream().map(Object::toString).reduce("", (a, b) -> a + "\n" + b));

        // The obfuscated form, built the way LOGIN7 builds it. Its bytes are
        // not text, so they are searched as an ISO-8859-1 string - one byte
        // per character, which is what the raw scan compares against.
        String obfuscated = new String(obfuscate(secret), StandardCharsets.ISO_8859_1);
        List<HeapDumpScanner.Finding> hidden = HeapDumpScanner.scanRaw(dump, obfuscated);
        assertTrue(hidden.isEmpty(),
                "the obfuscated password is in the heap dump - which is as bad, because the "
                        + "obfuscation needs no key to undo:\n"
                        + hidden.stream().map(Object::toString).reduce("", (a, b) -> a + "\n" + b));
    }

    /** UTF-16LE, nibbles swapped, XOR {@code 0xA5} - see {@code TdsPassword}. */
    private static byte[] obfuscate(String password) {
        byte[] utf16 = password.getBytes(StandardCharsets.UTF_16LE);
        byte[] hidden = new byte[utf16.length];
        for (int i = 0; i < utf16.length; i++) {
            int b = utf16[i] & 0xff;
            hidden[i] = (byte) ((((b & 0x0f) << 4) | (b >>> 4)) ^ 0xA5);
        }
        return hidden;
    }
}
