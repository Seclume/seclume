package space.seclume.heapcheck;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Properties;

import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

import com.sun.management.HotSpotDiagnosticMXBean;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.VirtualMachine;

/**
 * A heap dump of <b>another</b> process.
 *
 * <p>Three JDK mechanisms in a row, and each of them is the documented way to
 * do its step: the attach API joins the target process, its management agent is
 * started if it is not running yet, and the dump is asked for through the same
 * {@code HotSpotDiagnosticMXBean} a process uses on itself. Where the process
 * refuses that - a serialization filter that rejects what JMX sends over RMI,
 * as Helidon's does - the JDK's {@code jcmd} asks for the same dump through
 * the attach mechanism alone. No agent to
 * install, no tool outside the JDK, nothing that has to be prepared in advance -
 * which matters, because the whole point is to examine a process that was not
 * built with this in mind.
 *
 * <p>The dump is written by the <b>target</b> process, so the path is one it
 * can write, as it sees the file system - which is not this one when the
 * check runs in a container beside it - and the file belongs to its user.
 */
final class ProcessHeap {

    private ProcessHeap() {
    }

    /**
     * What the report says about the process: its JVM, and what it runs - the
     * main class or jar only, because the rest of the command line can hold
     * exactly what is being looked for.
     */
    record Jvm(String version, String vendor, String main) {
    }

    /**
     * Asks the process to write its heap to {@code target}, a path in the
     * process's file system that holds no file yet.
     *
     * @return what the process is
     * @throws IOException if the process cannot be attached to or refuses
     */
    static Jvm dump(String pid, Path target) throws IOException {
        VirtualMachine machine;
        try {
            machine = VirtualMachine.attach(pid);
        } catch (AttachNotSupportedException e) {
            throw new IOException("cannot attach to process " + pid + " - it has to be a "
                    + "Java process of the same user, and on some systems the same JDK "
                    + "version: " + e.getMessage(), e);
        }
        try {
            Properties properties = machine.getSystemProperties();
            String command = properties.getProperty("sun.java.command", "").strip();
            int space = command.indexOf(' ');
            Jvm jvm = new Jvm(properties.getProperty("java.runtime.version",
                    properties.getProperty("java.version", "?")),
                    properties.getProperty("java.vm.vendor", "?"),
                    space < 0 ? command : command.substring(0, space));
            try {
                String address = startAgent(machine);
                try (JMXConnector connector =
                             JMXConnectorFactory.connect(new JMXServiceURL(address))) {
                    MBeanServerConnection beans = connector.getMBeanServerConnection();
                    HotSpotDiagnosticMXBean diagnostic = java.lang.management.ManagementFactory
                            .newPlatformMXBeanProxy(beans,
                                    "com.sun.management:type=HotSpotDiagnostic",
                                    HotSpotDiagnosticMXBean.class);
                    // live = false: whatever is merely waiting to be collected is in
                    // the file too. That is the least forgiving setting and the only
                    // honest one - an attacker gets exactly this file, and whether an
                    // object in it was still reachable is of no interest to them.
                    diagnostic.dumpHeap(target.toAbsolutePath().toString(), false);
                }
            } catch (IOException | RuntimeException refused) {
                // A process with a serialization filter that rejects what JMX
                // sends over RMI - Helidon sets one that rejects everything - or
                // whose management agent cannot start: the same dump through
                // the attach mechanism's own command, without RMI.
                try {
                    jcmd(pid, target);
                } catch (IOException alsoRefused) {
                    alsoRefused.addSuppressed(refused);
                    throw new IOException("process " + pid + " refused the heap dump through JMX ("
                            + refused + ") and through jcmd (" + alsoRefused.getMessage() + ")",
                            alsoRefused);
                }
            }
            return jvm;
        } finally {
            machine.detach();
        }
    }

    /**
     * {@code jcmd <pid> GC.heap_dump -all <target>}: the dump through the
     * attach mechanism's diagnostic command, with this JDK's {@code jcmd}.
     * {@code -all} is {@code live = false}: unreachable objects as well. What
     * jcmd prints - where it dumped, how many bytes - is read only to explain a
     * failure.
     */
    static void jcmd(String pid, Path target) throws IOException {
        if (!pid.matches("[0-9]{1,10}")) {
            throw new IOException("a process id is a number, not '" + pid + "'");
        }
        boolean windows = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT)
                .startsWith("windows");
        Path jcmd = Path.of(System.getProperty("java.home"), "bin", windows ? "jcmd.exe" : "jcmd");
        if (!java.nio.file.Files.isExecutable(jcmd)) {
            throw new IOException("no jcmd in " + jcmd.getParent() + " - this needs a JDK, not a JRE");
        }
        Path output = java.nio.file.Files.createTempFile("seclume-heapcheck-jcmd", ".txt");
        try {
            Process process = new ProcessBuilder(jcmd.toString(), pid, "GC.heap_dump", "-all",
                    target.toAbsolutePath().toString())
                    .redirectErrorStream(true)
                    .redirectOutput(output.toFile())
                    .start();
            boolean finished;
            try {
                finished = process.waitFor(30, java.util.concurrent.TimeUnit.MINUTES);
            } catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
                throw new IOException("interrupted while process " + pid + " was dumping its heap", e);
            }
            if (!finished) {
                process.destroyForcibly();
                throw new IOException("jcmd did not finish within 30 minutes");
            }
            java.util.List<String> said = java.nio.file.Files.readAllLines(output);
            boolean failed = said.stream().anyMatch(line -> line.contains("Exception")
                    || line.startsWith("Error") || line.contains("Could not") || line.contains("failed"));
            if (process.exitValue() != 0 || failed) {
                throw new IOException("jcmd exited " + process.exitValue() + ": "
                        + String.join(" ", said.subList(Math.max(0, said.size() - 3), said.size())));
            }
        } finally {
            java.nio.file.Files.deleteIfExists(output);
        }
    }

    /**
     * The management agent of the target process, started if need be.
     *
     * <p>Every JVM can start it on demand; it listens on a local address only
     * and disappears with the process. Nothing is left behind, which is what
     * makes this usable on a machine somebody else has to run afterwards.
     */
    private static String startAgent(VirtualMachine machine) throws IOException {
        Properties agent = machine.getAgentProperties();
        String address = agent.getProperty("com.sun.management.jmxremote.localConnectorAddress");
        if (address != null) {
            return address;
        }
        return machine.startLocalManagementAgent();
    }
}
