package space.seclume.heapcheck;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.tck.HeapDumpScanner;

/**
 * A heap dump of another process - through JMX, and through {@code jcmd} where
 * the process refuses JMX: a serialization filter that rejects every class, as
 * Helidon sets one, makes the RMI call fail inside the target. The dump has to
 * be of that process: the text it holds is found in it.
 */
class ProcessHeapTest {

    /** The process to be dumped: holds a text, says so, and waits. */
    public static final class Target {
        static volatile String held;

        public static void main(String[] arguments) throws InterruptedException {
            held = arguments[0] + "-held-" + System.nanoTime();
            System.out.println("ready " + held.length());
            System.out.flush();
            Thread.sleep(TimeUnit.MINUTES.toMillis(3));
        }
    }

    private static Process start(String canary, String... options) throws IOException {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.addAll(List.of(options));
        command.addAll(List.of("-cp", System.getProperty("java.class.path"), Target.class.getName(), canary));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        BufferedReader output = new BufferedReader(new InputStreamReader(process.getInputStream(),
                StandardCharsets.UTF_8));
        // Lines before it - "Picked up JAVA_TOOL_OPTIONS" and the like - are the JVM's.
        List<String> before = new ArrayList<>();
        for (String line = output.readLine(); line != null; line = output.readLine()) {
            if (line.startsWith("ready")) {
                return process;
            }
            before.add(line);
        }
        process.destroyForcibly();
        throw new IllegalStateException("the target did not start: " + before);
    }

    private static void assertIsTheDumpOf(Path dump, String canary) throws IOException {
        assertTrue(Files.size(dump) > 1_000_000, "a heap dump, " + Files.size(dump) + " bytes");
        assertFalse(HeapDumpScanner.scan(dump, canary).isEmpty(),
                "the text the target holds is not in the dump - it is not that process's");
    }

    @Test
    void aProcessThatRefusesJmxIsDumpedThroughJcmd(@TempDir Path directory) throws Exception {
        String canary = "zlRefusesJmx" + Long.toHexString(System.nanoTime());
        Process target = start(canary, "-Djdk.serialFilter=!*");
        try {
            Path dump = directory.resolve("refusing.hprof");
            ProcessHeap.dump(Long.toString(target.pid()), dump);
            assertIsTheDumpOf(dump, canary);
        } finally {
            target.destroyForcibly();
        }
    }

    @Test
    void aPlainProcessIsDumpedAsBefore(@TempDir Path directory) throws Exception {
        String canary = "zlPlainJmx" + Long.toHexString(System.nanoTime());
        Process target = start(canary);
        try {
            Path dump = directory.resolve("plain.hprof");
            ProcessHeap.Jvm jvm = ProcessHeap.dump(Long.toString(target.pid()), dump);
            assertIsTheDumpOf(dump, canary);
            assertTrue(jvm.main().endsWith("ProcessHeapTest$Target"), jvm.main());
            assertFalse(jvm.main().contains(canary), "the arguments stay out of the report");
        } finally {
            target.destroyForcibly();
        }
    }

    @Test
    void jcmdAloneDumpsTooAndUnreachableObjectsAreIn(@TempDir Path directory) throws Exception {
        String canary = "zlJcmdAlone" + Long.toHexString(System.nanoTime());
        Process target = start(canary);
        try {
            Path dump = directory.resolve("jcmd.hprof");
            ProcessHeap.jcmd(Long.toString(target.pid()), dump);
            assertIsTheDumpOf(dump, canary);
        } finally {
            target.destroyForcibly();
        }
    }

    @Test
    void jcmdTakesNothingButAProcessId(@TempDir Path directory) {
        for (String pid : List.of("", "12 GC.run", "1;id", "-1", "12345678901", "$(id)")) {
            IOException e = assertThrows(IOException.class,
                    () -> ProcessHeap.jcmd(pid, directory.resolve("x.hprof")), "'" + pid + "'");
            assertTrue(e.getMessage().contains("a process id is a number"), e.getMessage());
        }
    }

    @Test
    void aProcessThatIsNotThereIsReportedNotDumped(@TempDir Path directory) {
        Path dump = directory.resolve("none.hprof");
        assertThrows(IOException.class, () -> ProcessHeap.dump("999999999", dump));
        assertThrows(IOException.class, () -> ProcessHeap.jcmd("999999999", dump));
        assertFalse(Files.exists(dump));
    }
}
