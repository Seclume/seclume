package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.jdbc.TlsStack;

/**
 * A network timeout counts only silence: a server that sends a byte before
 * each one runs out held a TLS handshake for as long as it liked. The
 * handshake has a deadline of its own now - seclume.loginBudgetFactor (3)
 * times the network timeout - on both stacks. The stand-in only trickles
 * bytes of a record it never finishes.
 */
@Timeout(30)
class HandshakeDeadlineTest {

    /** Announces a handshake record of 2^14 bytes, then sends one every 300 ms. */
    private static ServerSocket trickling() throws IOException {
        ServerSocket server = new ServerSocket(0, 5, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            while (!server.isClosed()) {
                try {
                    Socket accepted = server.accept();
                    Thread.ofVirtual().start(() -> {
                        try (Socket socket = accepted; OutputStream out = socket.getOutputStream()) {
                            out.write(new byte[] {0x16, 0x03, 0x03, 0x40, 0x00});
                            out.flush();
                            for (int i = 0; i < 100; i++) {
                                Thread.sleep(300);
                                out.write(0x02);
                                out.flush();
                            }
                        } catch (IOException | InterruptedException gone) {
                            // the client gave up - what the test wants
                        }
                    });
                } catch (IOException closing) {
                    return;
                }
            }
        });
        return server;
    }

    @ParameterizedTest
    @ValueSource(strings = {"SECLUME", "JSSE"})
    void aTricklingServerIsGivenUpOnWithinTheBudget(String stack) throws Exception {
        try (ServerSocket server = trickling()) {
            SocketTransport transport = SocketTransport.connect("localhost",
                    server.getLocalPort(), 5000);
            transport.networkTimeout(500);
            long started = System.nanoTime();
            IOException refused = assertThrows(IOException.class, () -> TlsLayers.start(
                    TlsStack.valueOf(stack), transport, "localhost", server.getLocalPort(), false));
            long took = (System.nanoTime() - started) / 1_000_000;
            assertTrue(took < 6000, "the handshake was held for " + took + " ms");
            assertTrue(String.valueOf(refused.getMessage()).contains("did not finish within 1500 ms"),
                    String.valueOf(refused));
            transport.close();
        }
    }

    @Test
    void withoutANetworkTimeoutThereIsNoDeadline() throws Exception {
        try (ServerSocket server = trickling()) {
            SocketTransport transport = SocketTransport.connect("localhost",
                    server.getLocalPort(), 5000);
            assertTrue(transport.networkTimeoutMillis() == 0);
            Thread handshake = Thread.ofVirtual().start(() -> {
                try {
                    TlsLayers.start(TlsStack.SECLUME, transport, "localhost",
                            server.getLocalPort(), false);
                } catch (IOException ended) {
                    // the transport closed below
                }
            });
            handshake.join(2500);
            assertTrue(handshake.isAlive(), "zero waits for ever, as it always did");
            transport.close();
            handshake.join(5000);
        }
    }
}
