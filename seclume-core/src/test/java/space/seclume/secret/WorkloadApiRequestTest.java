package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * What the client sends the agent, to the byte: the HTTP/2 preface, its
 * SETTINGS and window, a HEADERS frame of literal fields - among them
 * {@code workload.spiffe.io: true}, which the SPIFFE Workload API requires so
 * that a browser cannot be made to ask - and one gRPC message. Built here
 * apart from the client, frame by frame as RFC 9113 and RFC 7541 lay them out.
 */
@Timeout(30)
class WorkloadApiRequestTest {

    @Test
    void theRequestForAnX509SvidIsExactlyThis() throws Exception {
        byte[] expected = expectedRequest("/SpiffeWorkloadAPI/FetchX509SVID", new byte[0]);
        Path directory = Files.createTempDirectory("seclume-request");
        Path socket = directory.resolve("agent.sock");
        AtomicReference<byte[]> received = new AtomicReference<>();
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(socket));
            Thread agent = Thread.ofVirtual().start(() -> {
                try (SocketChannel client = server.accept()) {
                    ByteBuffer in = ByteBuffer.allocate(expected.length);
                    while (in.hasRemaining() && client.read(in) >= 0) {
                        // the whole request, and no more
                    }
                    received.set(java.util.Arrays.copyOf(in.array(), in.position()));
                } catch (IOException gone) {
                    // the client gave up
                }
            });
            assertThrows(IOException.class,
                    () -> new SpiffeWorkloadApi(socket, 5_000).fetchX509Svid(),
                    "this agent answers nothing");
            agent.join(5_000);
            assertArrayEquals(expected, received.get(), "the request the agent got");
        } finally {
            Files.deleteIfExists(socket);
            Files.deleteIfExists(directory);
        }
    }

    private static byte[] expectedRequest(String path, byte[] message) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        int window = 1 << 20;
        // SETTINGS (4): ENABLE_PUSH (2) = 0, INITIAL_WINDOW_SIZE (4) = 1 MiB.
        frame(out, 0x4, 0, 0, new byte[] {0, 2, 0, 0, 0, 0, 0, 4,
            (byte) (window >>> 24), (byte) (window >>> 16), (byte) (window >>> 8), (byte) window});
        // WINDOW_UPDATE (8) of the connection, up to the same window.
        frame(out, 0x8, 0, 0, int32(window - 65535));
        ByteArrayOutputStream block = new ByteArrayOutputStream();
        for (String[] field : new String[][] {{":method", "POST"}, {":scheme", "http"},
            {":path", path}, {":authority", "localhost"}, {"content-type", "application/grpc"},
            {"te", "trailers"}, {"workload.spiffe.io", "true"}}) {
            block.write(0x00);                       // literal, not indexed, a new name
            byte[] name = field[0].getBytes(StandardCharsets.US_ASCII);
            block.write(name.length);
            block.writeBytes(name);
            byte[] value = field[1].getBytes(StandardCharsets.US_ASCII);
            block.write(value.length);
            block.writeBytes(value);
        }
        frame(out, 0x1, 0x4, 1, block.toByteArray());   // HEADERS, END_HEADERS, stream 1
        ByteArrayOutputStream grpc = new ByteArrayOutputStream();
        grpc.write(0);                                  // not compressed
        grpc.writeBytes(int32(message.length));
        grpc.writeBytes(message);
        frame(out, 0x0, 0x1, 1, grpc.toByteArray());    // DATA, END_STREAM, stream 1
        return out.toByteArray();
    }

    private static void frame(ByteArrayOutputStream out, int type, int flags, int stream,
                              byte[] payload) {
        out.write(payload.length >>> 16);
        out.write(payload.length >>> 8);
        out.write(payload.length);
        out.write(type);
        out.write(flags);
        out.writeBytes(int32(stream));
        out.writeBytes(payload);
    }

    private static byte[] int32(int value) {
        return new byte[] {(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8),
            (byte) value};
    }
}
