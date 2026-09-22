package space.seclume.mysql.wire;

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
 * <p>The fourth and last of these. MySQL <b>does</b> wipe - {@code MyChannel}
 * has had the same two lines as the PostgreSQL channel all along - so unlike
 * the Oracle and SQL Server versions of this test, this one was green the
 * first time it ran.
 *
 * <p>It is worth having anyway, and the same afternoon proved why: the
 * invariant held in two of four channels and nobody knew which, because
 * nothing checked. An untested promise is a promise about the code as it is
 * today. The obvious optimisation here - wipe only as far as something was
 * actually written - would still look correct and would not be, and this is
 * where whoever tries it finds out, rather than in a security review.
 */
@Timeout(60)
class ReceiveBufferWipeTest {

    private static final String MARKER = "PAYLOAD-MARKER-MY-5a27ef-DO-NOT-KEEP-ME";

    /** Padding, so the marker does not sit where the next packet lands. */
    private static final String PAD = "x".repeat(64);

    @Test
    void aConsumedPacketIsNotLeftInTheBuffer() throws Exception {
        try (ServerSocketChannel listener = ServerSocketChannel.open()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
                    SocketChannel server = listener.accept()) {

                MyChannel channel = MyChannel.over(SocketTransport.wrap(client));

                send(server, 0, PAD + MARKER);
                channel.nextPacket();
                assertEquals(PAD + MARKER,
                        read(channel.packet(), PAD.length() + MARKER.length()));

                // Enough further packets to make the channel compact: it only
                // moves the bytes when the buffer is getting full, which is
                // the moment the wipe belongs to.
                for (int i = 0; i < 400; i++) {
                    send(server, i + 1, "ok");
                    channel.nextPacket();
                    read(channel.packet(), 2);
                }

                assertTrue(bufferOf(channel).indexOf(MARKER) < 0,
                        "the consumed payload is still in the receive buffer");
            }
        }
    }

    // ---- the small machinery ---------------------------------------------

    /** One MySQL packet: three length bytes, a sequence number, the payload. */
    private static void send(SocketChannel server, int sequence, String payload)
            throws IOException {
        byte[] bytes = payload.getBytes(StandardCharsets.US_ASCII);
        ByteBuffer out = ByteBuffer.allocate(4 + bytes.length);
        out.put((byte) bytes.length);
        out.put((byte) (bytes.length >>> 8));
        out.put((byte) (bytes.length >>> 16));
        out.put((byte) sequence);
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
    private static String bufferOf(MyChannel channel) throws Exception {
        Field field = MyChannel.class.getDeclaredField("in");
        field.setAccessible(true);
        WireBuffer buffer = (WireBuffer) field.get(channel);
        StringBuilder text = new StringBuilder(buffer.capacity());
        for (int i = 0; i < buffer.capacity(); i++) {
            text.append((char) (buffer.getByte(i) & 0xff));
        }
        return text.toString();
    }
}
