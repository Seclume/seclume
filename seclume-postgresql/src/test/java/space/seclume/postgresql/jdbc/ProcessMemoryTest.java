package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * The password is nowhere in the process - not only not on the heap.
 *
 * <p>{@code HeapDumpTest} shows what a heap dump holds. A heap dump is one way
 * a secret leaves a process; a core dump, a swap file, {@code gcore}, a
 * debugger and {@code /proc/pid/mem} are others, and they see everything:
 * native memory, OpenSSL's allocations, thread stacks, the JVM's own. So a
 * second JVM logs in to PostgreSQL over TLS with SCRAM - the password through
 * the secret provider, PBKDF2, the proof - and then this test reads every
 * readable region of that process through {@code /proc/<pid>/mem} and looks
 * for the password in UTF-8 and UTF-16.
 *
 * <p>The negative control comes first in importance: a child that holds the
 * password as a {@code String} has to be found, or a green run means only
 * that the search finds nothing.
 *
 * <p>Linux only. The parent may read its child's memory under Yama's default
 * {@code ptrace_scope} of 1.
 */
@Timeout(300)
class ProcessMemoryTest {

    private static final String HOST = System.getProperty("seclume.pgtls.host",
            TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.pgtls.port", 5433);

    private static Path passwordFile;

    @BeforeAll
    static void needsLinuxAndAServer() {
        Assumptions.assumeTrue(System.getProperty("os.name", "").toLowerCase().contains("linux"),
                "reads /proc/<pid>/mem - Linux only");
        for (Path candidate : List.of(Path.of(".local-pgtls-password"),
                Path.of("..", ".local-pgtls-password"))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(passwordFile != null, "no .local-pgtls-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no PostgreSQL with TLS on " + HOST + ":" + PORT);
        }
    }

    @Test
    void theNegativeControlIsFound() throws Exception {
        Scan scan = scanChild("leaking", 1);
        assertFalse(scan.findings().isEmpty(), "a password held as a String was not found - "
                + "the search proves nothing (" + scan + ")");
    }

    @Test
    void nothingIsLeftAfterTheConnectionsAreClosed() throws Exception {
        Scan scan = scanChild("closed", 3);
        assertTrue(scan.findings().isEmpty(), "the password is in the process: " + scan);
    }

    @Test
    void nothingIsThereWhileAConnectionIsOpen() throws Exception {
        Scan scan = scanChild("open", 3);
        assertTrue(scan.findings().isEmpty(), "the password is in the process: " + scan);
    }

    /** What was searched and what was found where. */
    record Scan(long bytes, int regions, List<String> findings) {
        @Override
        public String toString() {
            return (bytes >> 20) + " MB in " + regions + " regions, " + findings.size()
                    + " finding(s)" + (findings.isEmpty() ? "" : ": " + findings);
        }
    }

    private static Scan scanChild(String mode, int logins) throws Exception {
        Map<String, byte[]> needles = needles();
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED",
                "-cp", System.getProperty("java.class.path"),
                ProcessMemoryProbe.class.getName(),
                mode, HOST, Integer.toString(PORT), passwordFile.toString(),
                Integer.toString(logins)));
        // The child inherits this environment, and the kernel puts it at the
        // top of the child's stack: a password there would be found, and it
        // would say something about how the test was started, not about seclume.
        ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
        String utf8 = new String(needles.get("UTF-8"), StandardCharsets.UTF_8); // seclume-allow: the test's own process
        for (Map.Entry<String, String> variable : builder.environment().entrySet()) {
            assertFalse(variable.getValue().contains(utf8), "the environment variable "
                    + variable.getKey() + " holds the password, and the probe would inherit "
                    + "it - start the test without it");
        }
        Process child = builder.start();
        try {
            long pid = awaitReady(child);
            Scan scan = scan(pid, needles);
            assertTrue(scan.bytes() > 50L << 20, "too little memory read to mean anything: "
                    + scan);
            child.getOutputStream().write('\n');
            child.getOutputStream().flush();
            assertTrue(child.waitFor(30, TimeUnit.SECONDS), "the probe did not end");
            assertEquals(0, child.exitValue(), "the probe failed");
            return scan;
        } finally {
            child.destroyForcibly();
        }
    }

    private static long awaitReady(Process child) throws IOException {
        BufferedReader output = new BufferedReader(new InputStreamReader(
                child.getInputStream(), StandardCharsets.UTF_8));
        StringBuilder seen = new StringBuilder();
        String line;
        while ((line = output.readLine()) != null) {
            if (line.startsWith("READY ")) {
                return Long.parseLong(line.substring(6).trim());
            }
            seen.append(line).append('\n');
        }
        throw new AssertionError("the probe ended before it was ready:\n" + seen);
    }

    /** The password as the bytes it could be found as. */
    private static Map<String, byte[]> needles() throws IOException {
        String password = Files.readString(passwordFile, StandardCharsets.UTF_8).strip(); // seclume-allow: the test's own process, which is not searched
        Map<String, byte[]> needles = new LinkedHashMap<>();
        needles.put("UTF-8", password.getBytes(StandardCharsets.UTF_8));
        needles.put("UTF-16LE", password.getBytes(StandardCharsets.UTF_16LE));
        needles.put("UTF-16BE", password.getBytes(StandardCharsets.UTF_16BE));
        return needles;
    }

    private static Scan scan(long pid, Map<String, byte[]> needles) throws IOException {
        long bytes = 0;
        int regions = 0;
        List<String> findings = new ArrayList<>();
        byte[] buffer = new byte[16 << 20];
        int overlap = needles.values().stream().mapToInt(n -> n.length).max().orElse(1) - 1;
        try (RandomAccessFile memory = new RandomAccessFile("/proc/" + pid + "/mem", "r")) {
            for (String map : Files.readAllLines(Path.of("/proc/" + pid + "/maps"))) {
                String[] field = map.trim().split("\\s+");
                if (field[1].charAt(0) != 'r') {
                    continue;
                }
                String name = field.length > 5 ? field[5] : "[anonymous]";
                if (name.equals("[vvar]") || name.equals("[vsyscall]")) {
                    continue;
                }
                String[] range = field[0].split("-");
                long from = Long.parseUnsignedLong(range[0], 16);
                long to = Long.parseUnsignedLong(range[1], 16);
                regions++;
                // In windows that overlap by a needle's length, so that a
                // password across a window boundary is not missed.
                for (long at = from; at < to; at += buffer.length - overlap) {
                    int length = (int) Math.min(buffer.length, to - at);
                    try {
                        memory.seek(at);
                        memory.readFully(buffer, 0, length);
                    } catch (IOException unreadable) {
                        break;                            // a guard page, mapped but not readable
                    }
                    bytes += length;
                    for (Map.Entry<String, byte[]> needle : needles.entrySet()) {
                        for (int i = indexOf(buffer, length, needle.getValue(), 0); i >= 0;
                             i = indexOf(buffer, length, needle.getValue(), i + 1)) {
                            findings.add(needle.getKey() + " at 0x" + Long.toHexString(at + i)
                                    + " in " + name + " (" + field[1] + ")");
                        }
                    }
                    if (at + length >= to) {
                        break;
                    }
                }
            }
        }
        return new Scan(bytes, regions, findings.stream().distinct().toList());
    }

    private static int indexOf(byte[] haystack, int length, byte[] needle, int from) {
        byte first = needle[0];
        outer:
        for (int i = from; i <= length - needle.length; i++) {
            if (haystack[i] != first) {
                continue;
            }
            for (int j = 1; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
