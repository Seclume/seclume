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
        // Lines before it - "Picked up JAVA_TOOL_OPTIONS" and the like - are the JVM's.
        // The target writes nothing after "ready", so its output can be closed then.
        List<String> before = new ArrayList<>();
        try (BufferedReader output = new BufferedReader(new InputStreamReader(process.getInputStream(),
                StandardCharsets.UTF_8))) {
            for (String line = output.readLine(); line != null; line = output.readLine()) {
                if (line.startsWith("ready")) {
                    return process;
                }
                before.add(line);
            }
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

    /** Whether the process's management agent runs - asked through attach alone. */
    private static boolean agentRuns(Process target) throws Exception {
        com.sun.tools.attach.VirtualMachine machine =
                com.sun.tools.attach.VirtualMachine.attach(Long.toString(target.pid()));
        try {
            return machine.getAgentProperties().getProperty(
                    "com.sun.management.jmxremote.localConnectorAddress") != null;
        } finally {
            machine.detach();
        }
    }

    /**
     * The check leaves the process as it found it: no management agent - an
     * RMI connector without authentication, open until the process ends - is
     * started for the dump when jcmd can take it.
     */
    @Test
    void theDumpStartsNoManagementAgentInTheProcess(@TempDir Path directory) throws Exception {
        String canary = "zlNoAgent" + Long.toHexString(System.nanoTime());
        Process target = start(canary);
        try {
            assertFalse(agentRuns(target), "the agent ran before the check");
            Path dump = directory.resolve("no-agent.hprof");
            ProcessHeap.dump(Long.toString(target.pid()), dump);
            assertIsTheDumpOf(dump, canary);
            assertFalse(agentRuns(target), "the check left a management agent running");
        } finally {
            target.destroyForcibly();
        }
    }

    /** An agent that runs already is used as it is. */
    @Test
    void aRunningAgentIsUsed(@TempDir Path directory) throws Exception {
        String canary = "zlRunningAgent" + Long.toHexString(System.nanoTime());
        Process target = start(canary);
        try {
            com.sun.tools.attach.VirtualMachine machine =
                    com.sun.tools.attach.VirtualMachine.attach(Long.toString(target.pid()));
            try {
                machine.startLocalManagementAgent();
            } finally {
                machine.detach();
            }
            Path dump = directory.resolve("agent.hprof");
            ProcessHeap.dump(Long.toString(target.pid()), dump);
            assertIsTheDumpOf(dump, canary);
        } finally {
            target.destroyForcibly();
        }
    }

    @Test
    void aProcessOfThisFileSystemIsNotInAnother() {
        assertFalse(HeapCheck.otherFileSystem(Long.toString(ProcessHandle.current().pid())));
        assertFalse(HeapCheck.otherFileSystem("999999999"), "unknown is not another");
    }

    /**
     * A process in another mount namespace - another container - would write
     * its dump where this check cannot see it, and the dump would stay there:
     * refused before the dump, with --in-target as the way. Needs Linux, root
     * and unshare; skipped elsewhere.
     */
    @Test
    void aProcessInAnotherFileSystemIsRefusedAndLeftWithoutADump(@TempDir Path directory)
            throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.isDirectory(Path.of("/proc/self/ns"))
                && "root".equals(System.getProperty("user.name")), "Linux as root");
        Process probe = new ProcessBuilder("unshare", "-m", "--propagation", "private", "true")
                .redirectErrorStream(true).start();
        org.junit.jupiter.api.Assumptions.assumeTrue(probe.waitFor(30, TimeUnit.SECONDS)
                && probe.exitValue() == 0, "unshare -m");
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Process target = new ProcessBuilder("unshare", "-m", "--propagation", "private", "sh", "-c",
                "mount -t tmpfs tmpfs /tmp && exec \"$0\" -cp \"$1\" \"$2\" \"$3\"", java,
                System.getProperty("java.class.path"), Target.class.getName(), "zlOtherFs")
                .redirectErrorStream(true).start();
        try (BufferedReader output = new BufferedReader(new InputStreamReader(
                target.getInputStream(), StandardCharsets.UTF_8))) {
            for (String line = output.readLine(); line != null && !line.startsWith("ready");
                    line = output.readLine()) {
                // the JVM's own lines
            }
            long pid = target.descendants().filter(p -> p.info().command().orElse("")
                    .endsWith("java")).findFirst().map(ProcessHandle::pid).orElse(target.pid());
            assertTrue(HeapCheck.otherFileSystem(Long.toString(pid)));
            Path secret = Files.writeString(directory.resolve("secret"), "zlOtherFs");
            space.seclume.tck.ChildJvm.Result result = space.seclume.tck.ChildJvm.run(
                    HeapCheck.class, List.of("--pid", Long.toString(pid), "--secret-file",
                            secret.toString(), "--no-attribution"), 120);
            assertTrue(result.exitCode() == 2, result.output());
            assertTrue(result.output().contains("--in-target"), result.output());
            try (var left = Files.list(Path.of("/proc", Long.toString(pid), "root", "tmp"))) {
                assertTrue(left.noneMatch(f -> f.getFileName().toString()
                        .startsWith("seclume-heapcheck-")), "a dump was left in the process");
            }
        } finally {
            target.descendants().forEach(ProcessHandle::destroyForcibly);
            target.destroyForcibly();
        }
    }
}
