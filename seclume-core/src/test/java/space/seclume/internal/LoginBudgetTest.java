package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A driver's login has a budget as a whole: seclume.loginBudgetFactor (3)
 * times the connect timeout. The connect timeout counted silence only, and a
 * server that sent a byte now and then held a login - and a pool's thread and
 * permit - for as long as it liked.
 */
@Timeout(30)
class LoginBudgetTest {

    /** Accepts, then sends one byte every 200 ms for a minute. */
    private static ServerSocket dribbling() throws IOException {
        ServerSocket server = new ServerSocket(0, 5, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            try (Socket socket = server.accept(); OutputStream out = socket.getOutputStream()) {
                for (int i = 0; i < 300; i++) {
                    out.write('R');
                    out.flush();
                    Thread.sleep(200);
                }
            } catch (IOException | InterruptedException gone) {
                // closed by the budget - what the test wants
            }
        });
        return server;
    }

    @Test
    void aLoginThatDribblesIsClosedWithinTheBudget() throws Exception {
        try (ServerSocket server = dribbling()) {
            Transport transport = Transports.open("socket", "127.0.0.1", server.getLocalPort(), 500);
            long started = System.nanoTime();
            ByteBuffer one = ByteBuffer.allocateDirect(1);
            assertThrows(IOException.class, () -> {
                while (true) {
                    one.clear();
                    if (transport.read(one) < 0) {
                        throw new IOException("closed");
                    }
                }
            });
            long took = (System.nanoTime() - started) / 1_000_000;
            assertTrue(took < 5000, "the login was held for " + took + " ms");
            transport.close();
        }
    }

    @Test
    void aLoginThatIsDoneIsNotClosed() throws Exception {
        try (ServerSocket server = dribbling()) {
            Transport transport = Transports.open("socket", "127.0.0.1", server.getLocalPort(), 500);
            Transports.loggedIn(transport);
            Thread.sleep(2500);
            assertTrue(transport.isOpen(), "closed after the login was done");
            transport.close();
        }
    }
}
