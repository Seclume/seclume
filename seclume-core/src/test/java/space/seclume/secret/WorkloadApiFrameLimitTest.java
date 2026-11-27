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
}
