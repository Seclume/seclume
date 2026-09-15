package space.seclume.postgresql.wire;

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

import space.seclume.internal.WireBuffer;

/**
 * A consumed message does not stay in the receive buffer.
 *
 * <p>This library says in several places that a buffer which held payload is
 * wiped, and until now nothing checked it. The heap dump harness cannot: it
 * searches the Java heap, and these buffers are native memory beside it. So
 * the one promise that is genuinely hard to verify was the one taken on
 * trust.
 *
 * <p>The test needs no database. A pair of loopback sockets is enough to play
 * the server: write a message containing something unmistakable, let the
 * channel read it, then make the channel compact its buffer and look through
 * the whole of it for what was in that message.
 *
 * <p>What it is really pinning down is not the wiping call itself but the
 * <b>invariant behind it</b> - that after compaction no consumed byte is left
 * anywhere in the buffer. Somebody optimising the wipe later (there is an
 * obvious one: clear only as far as anything was written) will get an answer
 * from this test rather than from a security review.
 */
class ReceiveBufferWipeTest {

    /** Long enough not to occur by accident, and recognisable in a dump. */
    private static final String MARKER = "PAYLOAD-MARKER-9d4f2a1c-DO-NOT-KEEP-ME";

    /**
     * Padding in front of the marker, and the reason this test is worth
     * anything.
     *
     * <p>Without it the marker sat at the start of the buffer, where the next
     * message lands - and the first few bytes of it were simply overwritten,
     * so {@code indexOf} found nothing whether or not the buffer had been
     * wiped. The test passed for the wrong reason, which a control run with
     * the wipe removed showed: only the large case failed. Putting the marker
     * well beyond the reach of any follow-up message makes its absence mean
     * what it is supposed to mean.
     */
    private static final String PAD = "x".repeat(64);

    @Test
    void aConsumedMessageIsNotLeftInTheBuffer() throws Exception {
        try (ServerSocketChannel listener = ServerSocketChannel.open()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
                 SocketChannel server = listener.accept()) {

                PgChannel channel = PgChannel.wrap(client);

                // A message of the plainest possible shape: one tag byte, the
                // length, and a payload nobody could mistake for noise.
                send(server, (byte) 'D', PAD + MARKER);
                assertEquals((byte) 'D', channel.nextMessage());
                assertEquals(PAD + MARKER, read(channel.message(), PAD.length() + MARKER.length()));
                channel.endMessage();

                // The wipe happens when the buffer is compacted, and that is
                // where the next message begins. Without this the test would
                // be checking a buffer nobody had finished with.
                send(server, (byte) 'C', "done");
                assertEquals((byte) 'C', channel.nextMessage());
                channel.endMessage();

                assertTrue(bufferOf(channel).indexOf(MARKER) < 0,
                        "the consumed payload is still in the receive buffer");
            }
        }
    }

    /**
     * The same with a payload large enough to have been written far into the
     * buffer - a row of a real query is not forty bytes.
     */
    @Test
    void aLargeConsumedMessageIsNotLeftEither() throws Exception {
        String large = PAD + MARKER.repeat(200);          // some 7 KB
        try (ServerSocketChannel listener = ServerSocketChannel.open()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
                 SocketChannel server = listener.accept()) {

                PgChannel channel = PgChannel.wrap(client);
                send(server, (byte) 'D', large);
                assertEquals((byte) 'D', channel.nextMessage());
                assertEquals(large, read(channel.message(), large.length()));
                channel.endMessage();

                send(server, (byte) 'C', "done");
                assertEquals((byte) 'C', channel.nextMessage());
                channel.endMessage();

                assertTrue(bufferOf(channel).indexOf(MARKER) < 0,
                        "a large consumed payload is still in the receive buffer");
            }
        }
    }

    // ---- the small machinery ---------------------------------------------

    /** Writes one message the way the server would: tag, length, payload. */
    private static void send(SocketChannel server, byte tag, String payload) throws IOException {
        byte[] bytes = payload.getBytes(StandardCharsets.US_ASCII);
        ByteBuffer out = ByteBuffer.allocate(5 + bytes.length);
        out.put(tag);
        out.putInt(4 + bytes.length);
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
     * the channel considers filled. What is being looked for is exactly the
     * byte nobody expects to still be there.
     */
    private static String bufferOf(PgChannel channel) throws Exception {
        Field field = PgChannel.class.getDeclaredField("in");
        field.setAccessible(true);
        WireBuffer buffer = (WireBuffer) field.get(channel);
        StringBuilder text = new StringBuilder(buffer.capacity());
        for (int i = 0; i < buffer.capacity(); i++) {
            text.append((char) (buffer.getByte(i) & 0xff));
        }
        return text.toString();
    }
}
