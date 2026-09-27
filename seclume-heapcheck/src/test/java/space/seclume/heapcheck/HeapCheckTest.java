package space.seclume.heapcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The tool against two processes: one that holds the secret in a
 * {@code String} and one that does not.
 *
 * <p>Both halves matter. That it finds the secret in the first proves the
 * search works at all - a check that never finds anything is worth nothing, and
 * a green run would mean the opposite of what it seems to. That it finds
 * nothing in the second is what the tool is for.
 */
class HeapCheckTest {

    private static final String SECRET = "hunter2-seclume-heapcheck-probe";
    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    @Test
    void itFindsASecretThatIsHeldInAString(@TempDir Path directory) throws Exception {
        assertEquals(1, check(directory, Holder.class),
                "the secret was in that process and the tool did not find it");
    }

    @Test
    void itFindsNothingInAProcessThatKeepsNoSecret(@TempDir Path directory) throws Exception {
        assertEquals(0, check(directory, Empty.class),
                "the tool found a secret in a process that never had one");
    }

    /**
     * The audit run: a dump that exists, several secrets - one held, one not,
     * one binary - and both reports, which say which is which and hold none of
     * them.
     */
    @Test
    void anAuditOfAnExistingDumpWithSeveralSecrets(@TempDir Path directory) throws Exception {
        Path dump = directory.resolve("app.hprof");
        Path secrets = Files.createDirectory(directory.resolve("secrets"));
        Path held = secrets.resolve("db-password");
        Files.writeString(held, SECRET, StandardCharsets.UTF_8);
        Path other = secrets.resolve("api-key");
        String otherSecret = "never-in-that-heap-" + System.nanoTime();
        Files.writeString(other, otherSecret, StandardCharsets.UTF_8);
        Path binary = secrets.resolve("key.der");
        byte[] key = new byte[48];
        RANDOM.nextBytes(key);
        key[0] = (byte) 0xff;                     // not UTF-8: looked for as bytes
        Files.write(binary, key);

        // the dump, taken and kept by the tool itself - then checked as a file
        withProbe(held, Holder.class, pid ->
                assertEquals(1, HeapCheck.run(pid, held, dump)));
        assertTrue(Files.exists(dump), "--keep-dump did not keep the dump");

        Path markdown = directory.resolve("report.md");
        Path json = directory.resolve("report.json");
        int exit = HeapCheck.run(new HeapCheck.Options(null, dump,
                List.of(other, held, binary), List.of(markdown, json), null));
        assertEquals(1, exit, "one of the three secrets was in the heap");
        assertTrue(Files.exists(dump), "a dump that was given must not be deleted");

        String md = Files.readString(markdown);
        String js = Files.readString(json);
        assertTrue(md.contains("SECRET FOUND") && md.contains("1 of 3 secret(s)"), md);
        assertTrue(md.contains("| `" + held + "` | text | **FOUND**"), md);
        assertTrue(md.contains("| `" + other + "` | text | not found"), md);
        assertTrue(md.contains("| `" + binary + "` | binary | not found"), md);
        assertTrue(js.contains("\"verdict\": \"FOUND\""), js);
        assertTrue(js.contains("\"source\": " + AuditReport.quote(held.toString())
                + ",\n      \"kind\": \"text\",\n      \"result\": \"FOUND\""), js);
        for (String report : List.of(md, js)) {
            assertTrue(!report.contains(SECRET) && !report.contains(otherSecret),
                    "a report holds a secret");
        }
    }

    @Test
    void aCleanProcessGivesACleanReport(@TempDir Path directory) throws Exception {
        Path secretFile = directory.resolve("secret");
        Files.writeString(secretFile, SECRET, StandardCharsets.UTF_8);
        Path json = directory.resolve("clean.json");
        withProbe(secretFile, Empty.class, pid -> assertEquals(0, HeapCheck.run(
                new HeapCheck.Options(pid, null, List.of(secretFile), List.of(json), null))));
        String report = Files.readString(json);
        assertTrue(report.contains("\"verdict\": \"NOT_FOUND\"")
                && report.contains("\"pid\"") && report.contains("\"main\": "
                + AuditReport.quote(Empty.class.getName())), report);
    }

    interface Check {
        void with(String pid) throws Exception;
    }

    private static void withProbe(Path secretFile, Class<?> probe, Check check)
            throws Exception {
        Process process = new ProcessBuilder(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"),
                probe.getName(), secretFile.toString()))
                .redirectErrorStream(true)
                .start();
        try (BufferedReader output = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line = output.readLine();
            while (line != null && line.startsWith("Picked up ")) {
                line = output.readLine();         // the JVM announcing JAVA_TOOL_OPTIONS
            }
            assertTrue("ready".equals(line), "the probe said: " + line);
            check.with(String.valueOf(process.pid()));
        } finally {
            process.getOutputStream().close();
            if (!process.waitFor(30, TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        }
    }

    /**
     * Starts the probe, checks it, and stops it again.
     *
     * <p>The secret goes to the probe as a <b>file path</b>, never as an
     * argument - and that is not tidiness. The first version of this test
     * passed it on the command line, and then the process that holds nothing
     * contained it forty-four times: arguments live in the heap as
     * {@code String}s, in {@code sun.java.command}, and in the command line the
     * JVM keeps. The tool was right and the test was wrong, which is exactly
     * the mistake the tool exists to make visible.
     */
    private static int check(Path directory, Class<?> probe) throws Exception {
        Path secretFile = directory.resolve("secret");
        Files.writeString(secretFile, SECRET, StandardCharsets.UTF_8);

        Process process = new ProcessBuilder(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"),
                probe.getName(), secretFile.toString()))
                .redirectErrorStream(true)
                .start();
        try (BufferedReader output = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            // The probe says when it is ready; without that the dump might be
            // taken before the secret is even there.
            String line = output.readLine();
            while (line != null && line.startsWith("Picked up ")) {
                line = output.readLine();         // the JVM announcing JAVA_TOOL_OPTIONS
            }
            assertTrue("ready".equals(line), "the probe said: " + line);
            return HeapCheck.run(String.valueOf(process.pid()), secretFile, null);
        } finally {
            OutputStream in = process.getOutputStream();
            in.close();                           // the probe ends when stdin does
            if (!process.waitFor(30, TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        }
    }

    /** A process that does what almost every application does. */
    public static final class Holder {

        /** Held in a field so that no optimiser can argue it away. */
        static String password;

        public static void main(String[] arguments) throws Exception {
            // What almost every application does: read the secret into a
            // String and keep it.
            password = java.nio.file.Files.readString(Path.of(arguments[0]),
                    StandardCharsets.UTF_8); // seclume-allow: this probe leaks on purpose - see the class comment
            System.out.println("ready");
            System.out.flush();
            System.in.read();
            // Touched once at the very end, so the field is live until here.
            if (password.isEmpty()) {
                System.out.println("never");
            }
        }
    }

    /** And one that holds nothing at all. */
    public static final class Empty {

        public static void main(String[] arguments) throws Exception {
            System.out.println("ready");
            System.out.flush();
            System.in.read();
        }
    }
}
