package space.seclume.postgresql.wire;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;

import org.junit.jupiter.api.Test;

import space.seclume.internal.Transport;
import space.seclume.postgresql.PgProtocol;

/**
 * The driver reads and writes through a {@link Transport} and nothing else.
 *
 * <p>The refactoring that introduced the seam changed no behaviour, which is
 * the good part and also the problem: every existing test would pass just as
 * well if something underneath still reached for a {@code SocketChannel}. So
 * this one hands the channel a transport that is **not** a socket at all - no
 * file descriptor anywhere in it - and expects the driver to work.
 *
 * <p>The transport also does the most awkward legal thing it can: it delivers
 * <b>one byte per read</b>. That is allowed on any stream and almost never
 * happens on a loopback connection, which is why message framing is the kind of
 * code that works for years and then fails on a slow network. Here it has to
 * survive it on every message.
 */
class TransportSeamTest {

    /**
     * A transport over two byte queues. Reads hand out a single byte at a time.
     */
    private static final class Trickle implements Transport {
        private final Deque<Byte> incoming = new ArrayDeque<>();
        private final StringBuilder written = new StringBuilder();
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
                written.append((char) (from.get() & 0xff));
            }
            return written.length();
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
    void theDriverWorksOverATransportThatIsNotASocket() throws Exception {
        Trickle transport = new Trickle();
        // Two messages of the plainest shape: tag, length, payload.
        transport.server(message((byte) 'D', "first"));
        transport.server(message((byte) 'C', "second-and-longer"));

        PgChannel channel = PgChannel.over(transport);
        assertTrue(channel.isOpen());

        assertEquals((byte) 'D', channel.nextMessage());
        assertEquals("first", read(channel, 5));
        channel.endMessage();

        assertEquals((byte) 'C', channel.nextMessage());
        assertEquals("second-and-longer", read(channel, 17));
        channel.endMessage();

        channel.close();
        assertFalse(transport.isOpen(), "closing the channel has to close the transport");
    }

    /** And what the driver writes reaches the transport, byte for byte. */
    @Test
    void whatIsWrittenReachesTheTransport() throws Exception {
        Trickle transport = new Trickle();
        transport.server(message((byte) 'Z', "x"));

        PgChannel channel = PgChannel.over(transport);
        channel.begin(PgProtocol.SYNC);
        channel.end();
        channel.flush();

        // Sync is a tag and a length of four, and nothing else.
        assertEquals(5, transport.written.length());
        assertEquals((char) PgProtocol.SYNC, transport.written.charAt(0));
        assertEquals(4, transport.written.charAt(4));
        channel.close();
    }

    private static byte[] message(byte tag, String payload) {
        byte[] body = payload.getBytes(StandardCharsets.US_ASCII);
        ByteBuffer out = ByteBuffer.allocate(5 + body.length);
        out.put(tag).putInt(4 + body.length).put(body);
        return out.array();
    }

    private static String read(PgChannel channel, int length) {
        StringBuilder text = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            text.append((char) (channel.message().getByte() & 0xff));
        }
        return text.toString();
    }
}
