package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.WireBuffer;

/**
 * A consumed message does not stay in the receive buffer.
 *
 * <p>The PostgreSQL module has had this test for a while; SQL Server did not,
 * and did not hold the invariant. {@code TdsChannel.receive} begins each
 * message by resetting the pointers - not the memory - so the previous answer
 * stayed in the buffer for as long as it took something longer to cover it.
 * After a large result followed by a small one, that is never.
 *
 * <p><b>Why the heap dump harness cannot find this.</b> It searches the Java
 * heap; this buffer is native memory beside it. The promise that a buffer
 * which held payload is wiped was therefore the one taken on trust - and it is
 * not about passwords here but about rows, which is what one most wants not to
 * leave lying in a core dump.
 *
 * <p>No server needed: a pair of loopback sockets writes TDS packets, because
 * what is under test is the buffer arithmetic rather than the protocol.
 */
@Timeout(60)
class ReceiveBufferWipeTest {

    private static final String MARKER = "PAYLOAD-MARKER-TDS-2e94cb-DO-NOT-KEEP-ME";

    /**
     * Padding in front of the marker, so that its absence means something:
     * without it the marker sits where the next message lands and is
     * overwritten whether or not anything was wiped.
     */
    private static final String PAD = "x".repeat(64);

    @Test
    void aConsumedMessageIsNotLeftInTheBuffer() throws Exception {
        try (ServerSocketChannel listener = ServerSocketChannel.open()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
                    SocketChannel server = listener.accept()) {

                TdsChannel channel = TdsChannel.over(SocketTransport.wrap(client));

                send(server, PAD + MARKER);
                assertEquals(Tds.TYPE_TABULAR_RESULT, channel.receive());
                assertEquals(PAD + MARKER,
                        read(channel.message(), PAD.length() + MARKER.length()));

                // The next message is where the buffer is reused, so that is
                // where the wipe has to have happened. Deliberately short - a
                // long one would cover the evidence by accident.
                send(server, "ok");
                assertEquals(Tds.TYPE_TABULAR_RESULT, channel.receive());

                assertTrue(bufferOf(channel).indexOf(MARKER) < 0,
                        "the consumed payload is still in the receive buffer");
            }
        }
    }

    /** The same with a payload the size of a real result block. */
    @Test
    void aLargeConsumedMessageIsNotLeftEither() throws Exception {
        String large = PAD + MARKER.repeat(40);
        try (ServerSocketChannel listener = ServerSocketChannel.open()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
                    SocketChannel server = listener.accept()) {

                TdsChannel channel = TdsChannel.over(SocketTransport.wrap(client));

                send(server, large);
                assertEquals(Tds.TYPE_TABULAR_RESULT, channel.receive());
                assertEquals(large, read(channel.message(), large.length()));

                send(server, "ok");
                assertEquals(Tds.TYPE_TABULAR_RESULT, channel.receive());

                assertTrue(bufferOf(channel).indexOf(MARKER) < 0,
                        "a large consumed payload is still in the receive buffer");
            }
        }
    }

    // ---- the small machinery ---------------------------------------------

    /**
     * One TDS message as a single packet: header with the end-of-message bit,
     * then the payload. Short enough to stay under the default packet size,
     * which is what the channel expects of a server that agreed to it.
     */
    private static void send(SocketChannel server, String payload) throws IOException {
        byte[] bytes = payload.getBytes(StandardCharsets.US_ASCII);
        int length = Tds.HEADER_SIZE + bytes.length;
        ByteBuffer out = ByteBuffer.allocate(length);
        out.put((byte) Tds.TYPE_TABULAR_RESULT);
        out.put((byte) Tds.STATUS_END_OF_MESSAGE);
        out.put((byte) (length >>> 8));           // big-endian, the only such field
        out.put((byte) length);
        out.putShort((short) 0);                  // SPID
        out.put((byte) 1);                        // packet id
        out.put((byte) 0);                        // window
        out.put(bytes);
        out.flip();
        while (out.hasRemaining()) {
            server.write(out);
        }
    }

    private static String read(WireBuffer buffer, int length) {
        StringBuilder text = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            text.append((char) (buffer.getByte() & 0xff));
        }
        return text.toString();
    }

    /** The whole receive buffer as text, not only the part considered filled. */
    private static String bufferOf(TdsChannel channel) throws Exception {
        Field field = TdsChannel.class.getDeclaredField("in");
        field.setAccessible(true);
        WireBuffer buffer = (WireBuffer) field.get(channel);
        // Straight off the memory rather than through getByte(int), and the
        // distinction matters: this is looking for residue *beyond* the valid
        // region, which is precisely what the protocol accessor now refuses -
        // it gained a bounds check when the fuzz sweep found a decoder walking
        // past a buffer through it. A test that inspects memory should say so
        // and reach for the segment; a decoder should not be able to.
        java.lang.foreign.MemorySegment memory = buffer.segment();
        StringBuilder text = new StringBuilder(buffer.capacity());
        for (int i = 0; i < buffer.capacity(); i++) {
            text.append((char) (memory.get(
                    java.lang.foreign.ValueLayout.JAVA_BYTE, i) & 0xff));
        }
        return text.toString();
    }
}
