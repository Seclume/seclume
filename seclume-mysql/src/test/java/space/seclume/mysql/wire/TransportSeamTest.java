package space.seclume.mysql.wire;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.Transport;

/**
 * The MySQL channel reads and writes through a {@link Transport} and nothing
 * else - and its framing survives the stream arriving one byte at a time.
 *
 * <p>MySQL's framing is the simplest of the four and the one with the extra
 * field: three length bytes, then a <b>sequence number</b> that the server
 * checks and that the client has to continue rather than restart. One byte per
 * read spreads even that four-byte header across four calls, which is legal on
 * any stream and almost never happens on a loopback connection - the reason
 * framing code can work for years and then fail behind a proxy.
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
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.writeBytes(packet(0, "first payload"));
        stream.writeBytes(packet(1, "second payload"));
        transport.server(stream.toByteArray());

        MyChannel channel = MyChannel.over(transport);

        channel.nextPacket();
        assertEquals("first payload", payloadOf(channel, "first payload".length()));
        channel.nextPacket();
        assertEquals("second payload", payloadOf(channel, "second payload".length()));
    }

    /**
     * The sequence number is continued, not restarted.
     *
     * <p>It is the one field MySQL has that the other three do not, and the
     * server rejects a packet whose number does not follow - so a channel that
     * lost track of it would produce a connection that works until the first
     * answer and then does not.
     */
    @Test
    void theSequenceNumberFollowsTheServer() throws Exception {
        Trickle transport = new Trickle();
        transport.server(packet(7, "answer"));

        MyChannel channel = MyChannel.over(transport);
        channel.nextPacket();
        assertEquals("answer", payloadOf(channel, "answer".length()));

        // The next thing the client sends continues at eight.
        channel.beginPacket().putBytes(
                java.lang.foreign.MemorySegment.ofArray("x".getBytes(StandardCharsets.US_ASCII)),
                0, 1);
        channel.end();
        channel.flush();

        byte[] sent = transport.written.toByteArray();
        assertTrue(sent.length >= 5, "nothing reached the transport");
        assertEquals(8, sent[3] & 0xff,
                "the sequence number did not continue where the server left off");
    }

    /** What the channel writes goes to the transport and nowhere else. */
    @Test
    void whatIsWrittenReachesTheTransport() throws Exception {
        Trickle transport = new Trickle();
        MyChannel channel = MyChannel.over(transport);

        channel.beginCommand((byte) 0x0e);        // COM_PING
        channel.end();
        channel.flush();

        byte[] sent = transport.written.toByteArray();
        assertEquals(5, sent.length, "a ping is four header bytes and one command byte");
        assertEquals(1, sent[0] & 0xff, "the length field is wrong");
        assertEquals(0, sent[3] & 0xff, "a command starts a new sequence at zero");
        assertEquals(0x0e, sent[4] & 0xff, "the command byte did not survive");
    }

    // ---- the small machinery ---------------------------------------------

    /** One MySQL packet: three length bytes, the sequence number, the payload. */
    private static byte[] packet(int sequence, String payload) {
        byte[] bytes = payload.getBytes(StandardCharsets.US_ASCII);
        ByteBuffer out = ByteBuffer.allocate(4 + bytes.length);
        out.put((byte) bytes.length);
        out.put((byte) (bytes.length >>> 8));
        out.put((byte) (bytes.length >>> 16));
        out.put((byte) sequence);
        out.put(bytes);
        return out.array();
    }

    private static String payloadOf(MyChannel channel, int length) {
        StringBuilder text = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            text.append((char) (channel.packet().getByte() & 0xff));
        }
        return text.toString();
    }
}
