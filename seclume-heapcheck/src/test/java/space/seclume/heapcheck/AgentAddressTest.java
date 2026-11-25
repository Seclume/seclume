package space.seclume.heapcheck;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * heapcheck connected to whatever management agent address the examined
 * process published - a JNDI lookup, a remote RMI registry - from the process
 * that runs the check. Only a local connector's own address is used now;
 * anything else goes the jcmd way.
 */
class AgentAddressTest {

    @Test
    void aLocalConnectorIsTaken() {
        assertTrue(ProcessHeap.localConnector("service:jmx:rmi://127.0.0.1/stub/rO0ABXNy"));
        assertTrue(ProcessHeap.localConnector("service:jmx:rmi:///stub/rO0ABXNy"));
    }

    @Test
    void aJndiARemoteOrAnotherProtocolIsNot() {
        assertFalse(ProcessHeap.localConnector(
                "service:jmx:rmi:///jndi/rmi://attacker.example:1099/jmxrmi"));
        assertFalse(ProcessHeap.localConnector("service:jmx:rmi://attacker.example/stub/rO0AB"));
        assertFalse(ProcessHeap.localConnector("service:jmx:jmxmp://127.0.0.1:9999"));
        assertFalse(ProcessHeap.localConnector("not a url"));
    }
}
