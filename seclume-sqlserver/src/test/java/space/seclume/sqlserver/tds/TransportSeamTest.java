package space.seclume.sqlserver.tds;

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
 * The TDS channel reads and writes through a {@link Transport} and nothing
 * else - and its framing survives the stream arriving one byte at a time.
 *
 * <p>Worth repeating per driver because the framing differs in each, and TDS
 * has the awkward one: a message is split into packets, only the last of which
 * carries {@link Tds#STATUS_END_OF_MESSAGE}, and the channel reassembles them
 * by cutting each header out and moving everything behind it forward. That
 * arithmetic is invisible whenever an answer fits in one packet - which is
 * every answer on a loopback connection, and why the comment in
 * {@code receive} says this only showed up against a real server.
 *
 * <p><b>One byte per read</b> is legal on any stream and almost never happens
 * locally. Here every header and every boundary is spread across as many reads
 * as it has bytes.
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
    void oneMessageInOnePacketIsFramedByteByByte() throws Exception {
        Trickle transport = new Trickle();
        transport.server(packet("a single packet", true, 1));

        TdsChannel channel = TdsChannel.over(transport);

        assertEquals(Tds.TYPE_TABULAR_RESULT, channel.receive());
        assertEquals("a single packet", messageOf(channel));
    }

    /**
     * Three packets, one message - the case the loopback never produces.
     *
     * <p>The headers of the second and third have to disappear from the
     * reassembled message, and everything behind each of them has to move up
     * by exactly eight bytes. A mistake of one here yields a message that
     * parses into plausible nonsense rather than an error.
     */
    @Test
    void aMessageSplitAcrossPacketsIsPutBackTogether() throws Exception {
        Trickle transport = new Trickle();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.writeBytes(packet("first-", false, 1));
        stream.writeBytes(packet("second-", false, 2));
        stream.writeBytes(packet("third", true, 3));
        transport.server(stream.toByteArray());

        TdsChannel channel = TdsChannel.over(transport);

        assertEquals(Tds.TYPE_TABULAR_RESULT, channel.receive());
        assertEquals("first-second-third", messageOf(channel),
                "the packets were not reassembled into one message");
    }

    /**
     * And the message after it is read correctly too.
     *
     * <p>The reassembly moves bytes around inside the buffer, so the state it
     * leaves behind decides whether the next message is framed or shifted.
     * Checking one message proves only the easy half.
     */
    @Test
    void theMessageAfterASplitOneIsStillFramed() throws Exception {
        Trickle transport = new Trickle();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.writeBytes(packet("split-", false, 1));
        stream.writeBytes(packet("message", true, 2));
        stream.writeBytes(packet("after", true, 1));
        transport.server(stream.toByteArray());

        TdsChannel channel = TdsChannel.over(transport);

        assertEquals(Tds.TYPE_TABULAR_RESULT, channel.receive());
        assertEquals("split-message", messageOf(channel));
        assertEquals(Tds.TYPE_TABULAR_RESULT, channel.receive());
        assertEquals("after", messageOf(channel));
    }

    /** What the channel writes goes to the transport and nowhere else. */
    @Test
    void whatIsWrittenReachesTheTransport() throws Exception {
        Trickle transport = new Trickle();
        TdsChannel channel = TdsChannel.over(transport);

        channel.begin().putBytes(
                java.lang.foreign.MemorySegment.ofArray("hello".getBytes(StandardCharsets.US_ASCII)),
                0, 5);
        channel.send(Tds.TYPE_SQL_BATCH);

        byte[] sent = transport.written.toByteArray();
        assertTrue(sent.length > Tds.HEADER_SIZE, "nothing reached the transport");
        assertEquals(Tds.TYPE_SQL_BATCH, sent[0] & 0xff, "the packet type did not survive");
        assertEquals(Tds.STATUS_END_OF_MESSAGE, sent[1] & 0xff,
                "a single packet has to be marked as the end of the message");
    }

    // ---- the small machinery ---------------------------------------------

    /** One TDS packet: eight bytes of header, then the payload. */
    private static byte[] packet(String payload, boolean last, int id) {
        byte[] bytes = payload.getBytes(StandardCharsets.US_ASCII);
        int length = Tds.HEADER_SIZE + bytes.length;
        ByteBuffer out = ByteBuffer.allocate(length);
        out.put((byte) Tds.TYPE_TABULAR_RESULT);
        out.put((byte) (last ? Tds.STATUS_END_OF_MESSAGE : 0));
        out.put((byte) (length >>> 8));           // big-endian, the only such field
        out.put((byte) length);
        out.putShort((short) 0);                  // SPID
        out.put((byte) id);
        out.put((byte) 0);                        // window
        out.put(bytes);
        return out.array();
    }

    /** The reassembled message as text, from where the channel left the cursor. */
    private static String messageOf(TdsChannel channel) {
        int length = channel.messageLength() - channel.message().position();
        StringBuilder text = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            text.append((char) (channel.message().getByte() & 0xff));
        }
        return text.toString();
    }
}
