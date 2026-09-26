package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** A peer that never answers, and the watch that gives up on it. */
@Timeout(30)
class NetworkTimeoutsTest {

    @Test
    void aReadThatWaitsTooLongClosesTheConnectionAndSaysWhy() throws Exception {
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            SocketTransport transport = SocketTransport.connect("127.0.0.1",
                    silent.getLocalPort(), 2000);
            try (Socket accepted = silent.accept()) {
                assertTrue(accepted.isConnected());
                transport.networkTimeout(300);
                long start = System.nanoTime();
                SocketTimeoutException timeout = assertThrows(SocketTimeoutException.class,
                        () -> transport.read(ByteBuffer.allocate(16)));
                long millis = (System.nanoTime() - start) / 1_000_000;
                assertTrue(millis >= 290 && millis < 2000, "gave up after " + millis + " ms");
                assertTrue(timeout.getMessage().contains("300 ms"), timeout.getMessage());
                assertFalse(transport.isOpen(), "a connection that timed out stays open");
            }
        }
    }

    @Test
    void anAnswerInTimeIsReadAndZeroWaitsForEver() throws Exception {
        try (ServerSocket peer = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            SocketTransport transport = SocketTransport.connect("127.0.0.1",
                    peer.getLocalPort(), 2000);
            try (Socket accepted = peer.accept()) {
                transport.networkTimeout(2000);
                accepted.getOutputStream().write(7);
                ByteBuffer into = ByteBuffer.allocate(4);
                assertEquals(1, transport.read(into));

                // Switched off again: a pause longer than the old timeout is waited out.
                transport.networkTimeout(0);
                Thread writer = Thread.ofVirtual().start(() -> {
                    try {
                        Thread.sleep(2500);
                        accepted.getOutputStream().write(8);
                    } catch (Exception ignored) {
                        // The read below fails if this does.
                    }
                });
                into.clear();
                assertEquals(1, transport.read(into));
                assertEquals(8, into.get(0));
                writer.join();
                assertTrue(transport.isOpen());
            } finally {
                transport.close();
            }
        }
    }

    @Test
    void aNegativeTimeoutIsRefused() throws Exception {
        try (ServerSocket peer = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            SocketTransport transport = SocketTransport.connect("127.0.0.1",
                    peer.getLocalPort(), 2000);
            try (Socket accepted = peer.accept()) {
                assertTrue(accepted.isConnected());
                assertThrows(java.io.IOException.class, () -> transport.networkTimeout(-1));
            } finally {
                transport.close();
            }
        }
    }
}
