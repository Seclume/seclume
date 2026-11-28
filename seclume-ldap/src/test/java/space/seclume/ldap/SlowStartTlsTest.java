package space.seclume.ldap;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * StartTLS answered a byte at a time, each just before the read timeout would
 * run out - a response that announces 60000 bytes. No read times out; the
 * connect - StartTLS and the handshake - has three times the read timeout as a
 * whole, and gives up then.
 */
@Timeout(60)
class SlowStartTlsTest {

    @Test
    void aStartTlsAnswerThatNeverEndsIsGivenUpOn() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread.ofVirtual().start(() -> {
                try (Socket client = listener.accept()) {
                    client.getInputStream().read(new byte[64]);
                    OutputStream out = client.getOutputStream();
                    out.write(new byte[] {0x30, (byte) 0x83, 0x00, (byte) 0xea, 0x60});
                    for (int i = 0; i < 60_000; i++) {
                        out.write(0);
                        out.flush();
                        Thread.sleep(700);
                    }
                } catch (IOException | InterruptedException clientGone) {
                    // the client gave up - what the test wants
                }
            });
            int port = listener.getLocalPort();
            java.nio.file.Path secret = java.nio.file.Files.createTempFile("slow", ".pw");
            try {
                SeclumeLdap.of("ldap://127.0.0.1:" + port + "/dc=example?user=cn=svc&provider=file&path="
                        + secret.toString().replace('\\', '/') + "&timeout=1000&connectTimeout=1000");
                long started = System.nanoTime();
                SocketTimeoutException late = assertThrows(SocketTimeoutException.class, () -> {
                    try (LdapSocket socket = new LdapSocket()) {
                        socket.connect(new InetSocketAddress("127.0.0.1", port), 1000);
                    }
                });
                long took = System.nanoTime() - started;
                assertTrue(took < 10_000_000_000L, "the connect took " + took / 1_000_000 + " ms");
                assertTrue(late.getMessage().contains("did not finish within 3 s"), late.toString());
            } finally {
                java.nio.file.Files.deleteIfExists(secret);
            }
        }
    }

    @Test
    void theBudgetIsTheReadTimeoutTimesTheFactor() {
        assertTrue(LdapSocket.budgetSeconds(0) == 0);
        assertTrue(LdapSocket.budgetSeconds(1000) == 3);
        assertTrue(LdapSocket.budgetSeconds(10_000) == 30);
    }
}
