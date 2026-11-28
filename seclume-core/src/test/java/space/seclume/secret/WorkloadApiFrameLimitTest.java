package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A Workload API answering with a SETTINGS frame that announces 16 MiB had
 * that much allocated for it before a byte of it arrived. A frame other than
 * DATA is at most HTTP/2's default frame size, 16 KiB: one announced larger
 * is refused from its header, and nothing more is read.
 */
@Timeout(30)
class WorkloadApiFrameLimitTest {

    @Test
    void aSettingsFrameOf16MibIsRefusedFromItsHeader() throws Exception {
        Path directory = Files.createTempDirectory("seclume-frame-limit");
        Path socket = directory.resolve("agent.sock");
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(socket));
            Thread agent = Thread.ofVirtual().start(() -> {
                try (SocketChannel client = server.accept()) {
                    client.read(ByteBuffer.allocate(24));             // the preface
                    // A SETTINGS frame announcing 0xffffff bytes - and none of them.
                    client.write(ByteBuffer.wrap(new byte[] {
                        (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x04, 0x00, 0, 0, 0, 0}));
                    Thread.sleep(20_000);
                } catch (IOException | InterruptedException gone) {
                    // the client gave up - what the test wants
                }
            });
            long started = System.nanoTime();
            SpiffeWorkloadApi api = new SpiffeWorkloadApi(socket, 10_000);
            IOException refused = assertThrows(IOException.class, api::fetchX509Svid);
            long took = (System.nanoTime() - started) / 1_000_000;
            assertTrue(String.valueOf(refused.getMessage()).contains("at most "
                    + SpiffeWorkloadApi.MAX_CONTROL_FRAME), refused.toString());
            assertTrue(took < 5_000, "the refusal waited for the frame's bytes: " + took + " ms");
            agent.interrupt();
        } finally {
            Files.deleteIfExists(socket);
            Files.deleteIfExists(directory);
        }
    }

    /** A frame of exactly 16 KiB is HTTP/2's default and is read - an unknown type, then ignored. */
    @Test
    void aFrameOfExactly16KibIsRead() throws Exception {
        Path directory = Files.createTempDirectory("seclume-frame-limit");
        Path socket = directory.resolve("agent.sock");
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(socket));
            Thread agent = Thread.ofVirtual().start(() -> {
                try (SocketChannel client = server.accept()) {
                    client.read(ByteBuffer.allocate(24));             // the preface
                    int length = SpiffeWorkloadApi.MAX_CONTROL_FRAME;
                    ByteBuffer frame = ByteBuffer.allocate(9 + length);
                    frame.put((byte) (length >>> 16)).put((byte) (length >>> 8)).put((byte) length)
                            .put((byte) 0x0a).put((byte) 0).putInt(0);    // a type nobody defined
                    frame.position(9 + length).flip();
                    while (frame.hasRemaining()) {
                        client.write(frame);
                    }
                } catch (IOException gone) {
                    // the client gave up
                }
            });
            SpiffeWorkloadApi api = new SpiffeWorkloadApi(socket, 10_000);
            IOException ended = assertThrows(IOException.class, api::fetchX509Svid);
            assertTrue(!String.valueOf(ended.getMessage()).contains("at most"),
                    "a frame of the default size was refused: " + ended);
            agent.join(5_000);
        } finally {
            Files.deleteIfExists(socket);
            Files.deleteIfExists(directory);
        }
    }
}
