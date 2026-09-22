package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.Transport;

/**
 * The Oracle channel reads and writes through a {@link Transport} and nothing
 * else - and its framing survives the stream arriving one byte at a time.
 *
 * <p>The PostgreSQL module has had this test since the seam was introduced;
 * the other three did not, and the reason it is worth repeating is that the
 * framing is different in each. Oracle's is the most intricate of the four: a
 * length field that is two bytes or four depending on what was negotiated,
 * and a buffer that carries whatever arrived beyond the current packet over to
 * the next call - the mechanism that exists because two markers arrive in one
 * go, and the one this test would notice a mistake in.
 *
 * <p><b>One byte per read</b> is legal on any stream and almost never happens
 * on a loopback connection, which is why framing is the kind of code that
 * works for years and then fails on a slow network or behind a proxy. Here it
 * has to survive it on every packet.
 */
@Timeout(60)
class TransportSeamTest {

    /** A transport over two byte queues - no file descriptor anywhere in it. */
    private static final class Trickle implements Transport {
        private final Deque<Byte> incoming = new ArrayDeque<>();
        private final ByteArrayOutputStream written = new ByteArrayOutputStream();
        private boolean open = true;

        void server(byte[] bytes) {
            for (byte value : bytes) {
                incoming.add(value);
            }
        }

        @Override
        public int read(ByteBuffer into) throws IOException {
            if (incoming.isEmpty()) {
                throw new IOException("the test server has nothing more to say");
            }
            into.put(incoming.poll());
            return 1;                      // one byte, every time
        }

        @Override
        public int write(ByteBuffer from) {
            while (from.hasRemaining()) {
                written.write(from.get());
            }
            return written.size();
        }

        @Override
        public boolean isOpen() {
            return open;
        }

        @Override
        public void close() {
            open = false;
        }
    }

    @Test
    void packetsAreFramedEvenWhenTheStreamArrivesOneByteAtATime() throws Exception {
        Trickle transport = new Trickle();
        transport.server(data(true, "first payload"));
        transport.server(data(true, "second payload"));

        NsChannel channel = NsChannel.over(transport, NsPacket.VERSION_DESIRED);

        assertEquals(NsPacket.TYPE_DATA, channel.nextPacket());
        assertEquals("first payload", payloadOf(channel, "first payload".length()));
        assertEquals(NsPacket.TYPE_DATA, channel.nextPacket());
        assertEquals("second payload", payloadOf(channel, "second payload".length()));
    }

    /**
     * The short length field, which older servers still negotiate.
     *
     * <p>Two bytes or four is a negotiated fact, and reading it at the wrong
     * width loses the framing on the first packet - so both widths belong in a
     * test rather than only the one this machine happens to speak.
     */
    @Test
    void theShortLengthFieldIsFramedTheSameWay() throws Exception {
        Trickle transport = new Trickle();
        transport.server(data(false, "short form"));

        NsChannel channel = NsChannel.over(transport, NsPacket.VERSION_MINIMUM);

        assertEquals(NsPacket.TYPE_DATA, channel.nextPacket());
        assertEquals("short form", payloadOf(channel, "short form".length()));
    }

    /**
     * Two packets in one delivery, which is what the carry-over exists for.
     *
     * <p>Not an invented case: the server sends a break marker and a reset
     * marker together, and a client that dropped the second would wait for a
     * packet it has already read. With one byte per read the two are spread
     * even more thinly, so if the leftover arithmetic is wrong at all it is
     * wrong here.
     */
    @Test
    void aSecondPacketInTheSameDeliveryIsNotLost() throws Exception {
        Trickle transport = new Trickle();
        ByteArrayOutputStream both = new ByteArrayOutputStream();
        both.writeBytes(marker(NsPacket.MARKER_TYPE_BREAK));
        both.writeBytes(marker(NsPacket.MARKER_TYPE_RESET));
        both.writeBytes(data(true, "after the markers"));
        transport.server(both.toByteArray());

        NsChannel channel = NsChannel.over(transport, NsPacket.VERSION_DESIRED);

        assertEquals(NsPacket.TYPE_MARKER, channel.nextPacket());
        assertEquals(NsPacket.MARKER_TYPE_BREAK, channel.markerType());
        assertEquals(NsPacket.TYPE_MARKER, channel.nextPacket());
        assertEquals(NsPacket.MARKER_TYPE_RESET, channel.markerType());
        assertEquals(NsPacket.TYPE_DATA, channel.nextPacket());
        assertEquals("after the markers", payloadOf(channel, "after the markers".length()));
    }

    /** What the channel writes goes to the transport and nowhere else. */
    @Test
    void whatIsWrittenReachesTheTransport() throws Exception {
        Trickle transport = new Trickle();
        NsChannel channel = NsChannel.over(transport, NsPacket.VERSION_DESIRED);

        channel.sendMarker(NsPacket.MARKER_RESET);

        byte[] sent = transport.written.toByteArray();
        assertTrue(sent.length >= NsPacket.HEADER_SIZE,
                "nothing reached the transport: " + sent.length + " bytes");
        assertEquals(NsPacket.TYPE_MARKER, sent[4] & 0xff,
                "what was written is not a marker packet");
    }

    // ---- the small machinery ---------------------------------------------

    private static byte[] data(boolean large, String payload) {
        byte[] bytes = payload.getBytes(StandardCharsets.US_ASCII);
        int length = NsPacket.HEADER_SIZE + NsPacket.DATA_FLAGS_SIZE + bytes.length;
        ByteBuffer out = ByteBuffer.allocate(length);
        header(out, large, length, NsPacket.TYPE_DATA);
        out.putShort((short) 0x2000);             // data flags: end of answer
        out.put(bytes);
        return out.array();
    }

    private static byte[] marker(int kind) {
        int length = NsPacket.HEADER_SIZE + 3;
        ByteBuffer out = ByteBuffer.allocate(length);
        header(out, true, length, NsPacket.TYPE_MARKER);
        out.put((byte) 1);
        out.put((byte) 0);
        out.put((byte) kind);
        return out.array();
    }

    /** Eight bytes either way: the large form takes the checksum's two. */
    private static void header(ByteBuffer out, boolean large, int length, int type) {
        if (large) {
            out.putInt(length);
        } else {
            out.putShort((short) length);
            out.putShort((short) 0);              // packet checksum
        }
        out.put((byte) type);
        out.put((byte) 0);                        // flags
        out.putShort((short) 0);                  // header checksum
    }

    private static String payloadOf(NsChannel channel, int length) {
        StringBuilder text = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            text.append((char) (channel.packet().getByte() & 0xff));
        }
        return text.toString();
    }
}
