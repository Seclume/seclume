package space.seclume.oracle.net;

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
 * A consumed packet does not stay in the receive buffer.
 *
 * <p>The PostgreSQL module has had this test for a while; the other three did
 * not, and two of them did not hold the invariant. This is the Oracle half of
 * that: {@code NsChannel.nextPacket} moves whatever the socket delivered
 * beyond the last packet to the front of the buffer - and left everything
 * behind it exactly where it was. The bytes of the packet just consumed
 * therefore stayed in native memory until something longer happened to
 * overwrite them, which for a short answer after a long one is never.
 *
 * <p><b>Why this cannot be found by the heap dump harness.</b> That searches
 * the Java heap; these buffers are native memory beside it. So the promise
 * that a buffer which held payload is wiped is exactly the one that was taken
 * on trust - and it is not about passwords but about rows: a query result is
 * the thing most worth not leaving in a core dump.
 *
 * <p>No database needed. A pair of loopback sockets plays the server, because
 * what is under test is the buffer arithmetic and not the protocol.
 */
@Timeout(60)
class ReceiveBufferWipeTest {

    /** Long enough not to occur by accident, and recognisable in a dump. */
    private static final String MARKER = "PAYLOAD-MARKER-ORA-7b31fd-DO-NOT-KEEP-ME";

    /**
     * Padding in front of the marker.
     *
     * <p>Without it the marker would sit where the next packet lands and be
     * overwritten whether or not anything was wiped - the test would pass for
     * the wrong reason. The PostgreSQL version of this test was written twice
     * for exactly that reason; this one starts where that one ended up.
     */
    private static final String PAD = "x".repeat(64);

    @Test
    void aConsumedPacketIsNotLeftInTheBuffer() throws Exception {
        try (ServerSocketChannel listener = ServerSocketChannel.open()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
                    SocketChannel server = listener.accept()) {

                NsChannel channel = NsChannel.over(SocketTransport.wrap(client),
                        NsPacket.VERSION_DESIRED);

                sendData(server, PAD + MARKER);
                assertEquals(NsPacket.TYPE_DATA, channel.nextPacket());
                assertEquals(PAD + MARKER, read(channel.packet(), PAD.length() + MARKER.length()));

                // The next packet is where the buffer is rearranged, so that
                // is where the wipe has to have happened. Deliberately short -
                // a long one would overwrite the evidence by accident.
                sendData(server, "ok");
                assertEquals(NsPacket.TYPE_DATA, channel.nextPacket());

                assertTrue(bufferOf(channel).indexOf(MARKER) < 0,
                        "the consumed payload is still in the receive buffer");
            }
        }
    }

    /** The same with a payload the size of a real row block. */
    @Test
    void aLargeConsumedPacketIsNotLeftEither() throws Exception {
        String large = PAD + MARKER.repeat(100);
        try (ServerSocketChannel listener = ServerSocketChannel.open()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
                    SocketChannel server = listener.accept()) {

                NsChannel channel = NsChannel.over(SocketTransport.wrap(client),
                        NsPacket.VERSION_DESIRED);

                sendData(server, large);
                assertEquals(NsPacket.TYPE_DATA, channel.nextPacket());
                assertEquals(large, read(channel.packet(), large.length()));

                sendData(server, "ok");
                assertEquals(NsPacket.TYPE_DATA, channel.nextPacket());

                assertTrue(bufferOf(channel).indexOf(MARKER) < 0,
                        "a large consumed payload is still in the receive buffer");
            }
        }
    }

    // ---- the small machinery ---------------------------------------------

    /** One DATA packet, the way the server writes it: header, flags, payload. */
    private static void sendData(SocketChannel server, String payload) throws IOException {
        byte[] bytes = payload.getBytes(StandardCharsets.US_ASCII);
        int length = NsPacket.HEADER_SIZE + NsPacket.DATA_FLAGS_SIZE + bytes.length;
        ByteBuffer out = ByteBuffer.allocate(length);
        out.putInt(length);                       // the large length form
        out.put((byte) NsPacket.TYPE_DATA);
        out.put((byte) 0);                        // flags
        out.putShort((short) 0);                  // header checksum
        out.putShort((short) 0x2000);             // data flags: end of answer
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

    /**
     * The whole receive buffer as text - every byte of it, not only the part
     * the channel considers filled. What is looked for is exactly the byte
     * nobody expects to still be there.
     */
    private static String bufferOf(NsChannel channel) throws Exception {
        Field field = NsChannel.class.getDeclaredField("in");
        field.setAccessible(true);
        WireBuffer buffer = (WireBuffer) field.get(channel);
        StringBuilder text = new StringBuilder(buffer.capacity());
        for (int i = 0; i < buffer.capacity(); i++) {
            text.append((char) (buffer.getByte(i) & 0xff));
        }
        return text.toString();
    }
}
