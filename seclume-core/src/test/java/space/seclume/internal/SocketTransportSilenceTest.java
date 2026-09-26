package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A connection cut after a silence says so - "Got minus one from a read call"
 * tells nobody that a firewall forgot the flow - and every connection has TCP
 * keepalive on, so fewer of them are cut at all.
 */
@Timeout(30)
class SocketTransportSilenceTest {

    @AfterEach
    void restore() {
        SocketTransport.quietMillis = 30_000;
    }

    @Test
    void everyConnectionKeepsAlive() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
             SocketTransport transport = SocketTransport.connect("127.0.0.1",
                     server.getLocalPort(), 2000);
             Socket accepted = server.accept()) {
            assertTrue(accepted.isConnected());
            assertTrue(transport.keepsAlive(), "no keepalive on a driver's connection");
        }
    }

    @Test
    void aConnectionEndedAfterSilenceSaysHowLongItWasQuiet() throws Exception {
        SocketTransport.quietMillis = 200;
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            CompletableFuture<Void> peer = CompletableFuture.runAsync(() -> {
                try (Socket accepted = server.accept()) {
                    accepted.getInputStream().read();          // one byte of "traffic"
                    Thread.sleep(600);                         // then silence, then gone
                } catch (IOException | InterruptedException e) {
                    throw new IllegalStateException(e);
                }
            });
            try (SocketTransport transport = SocketTransport.connect("127.0.0.1",
                    server.getLocalPort(), 2000)) {
                transport.write(ByteBuffer.wrap(new byte[] {1}));
                peer.get(10, TimeUnit.SECONDS);
                IOException cut = assertThrows(IOException.class,
                        () -> transport.read(ByteBuffer.allocate(16)));
                assertTrue(cut.getMessage().contains("without traffic"), cut.getMessage());
                assertTrue(cut.getMessage().contains("idle timeout"), cut.getMessage());
            }
        }
    }

    @Test
    void anEndWithoutSilenceIsAnOrdinaryEndOfStream() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            CompletableFuture<Void> peer = CompletableFuture.runAsync(() -> {
                try (Socket accepted = server.accept()) {
                    accepted.getInputStream().read();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            });
            try (SocketTransport transport = SocketTransport.connect("127.0.0.1",
                    server.getLocalPort(), 2000)) {
                transport.write(ByteBuffer.wrap(new byte[] {1}));
                peer.get(10, TimeUnit.SECONDS);
                assertEquals(-1, transport.read(ByteBuffer.allocate(16)));
            }
        }
    }
}
