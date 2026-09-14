package space.seclume.heapcheck;

import java.io.IOException;
import java.nio.file.Files;
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
 * {@code HotSpotDiagnosticMXBean} a process uses on itself. No agent to
 * install, no tool outside the JDK, nothing that has to be prepared in advance -
 * which matters, because the whole point is to examine a process that was not
 * built with this in mind.
 *
 * <p>The dump is written by the <b>target</b> process, so the path is one it
 * can write and the file belongs to its user.
 */
final class ProcessHeap {

    private ProcessHeap() {
    }

    /**
     * Asks the process to write its heap to {@code target}.
     *
     * @throws IOException if the process cannot be attached to or refuses
     */
    static void dump(String pid, Path target) throws IOException {
        VirtualMachine machine;
        try {
            machine = VirtualMachine.attach(pid);
        } catch (AttachNotSupportedException e) {
            throw new IOException("cannot attach to process " + pid + " - it has to be a "
                    + "Java process of the same user, and on some systems the same JDK "
                    + "version: " + e.getMessage(), e);
        }
        try {
            String address = startAgent(machine);
            try (JMXConnector connector =
                         JMXConnectorFactory.connect(new JMXServiceURL(address))) {
                MBeanServerConnection beans = connector.getMBeanServerConnection();
                HotSpotDiagnosticMXBean diagnostic = java.lang.management.ManagementFactory
                        .newPlatformMXBeanProxy(beans,
                                "com.sun.management:type=HotSpotDiagnostic",
                                HotSpotDiagnosticMXBean.class);
                Files.deleteIfExists(target);
                // live = false: whatever is merely waiting to be collected is in
                // the file too. That is the least forgiving setting and the only
                // honest one - an attacker gets exactly this file, and whether an
                // object in it was still reachable is of no interest to them.
                diagnostic.dumpHeap(target.toAbsolutePath().toString(), false);
            }
        } finally {
            machine.detach();
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
