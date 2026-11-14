package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Deque;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.Transport;

/**
 * An ATTENTION is owed from the moment it can reach the server, not from the
 * moment its write returned.
 *
 * <p>The server answers fast: the interrupted batch ends at once, and the
 * thread that sent the statement reads that answer and asks
 * {@link TdsChannel#drainAttention} whether a cancellation is owed - while
 * the cancelling thread may still be inside the write of those eight bytes.
 * Counted after the write, the reader saw nothing owed: the statement
 * returned normally although the server had stopped it, and the
 * acknowledgement was left at the head of the next answer. The SQL Server job
 * of pull request #345 failed so in LocalCancelTest: {@code waitfor delay
 * '00:00:30'} cancelled after half a second, ended after half a second, and
 * reported no cancellation.
 *
 * <p>Here the transport plays the reader: inside the write of the ATTENTION
 * it asks the channel what is owed, as the other thread can.
 */
@Timeout(30)
class AttentionCountedBeforeSentTest {

    /** A transport that, inside the write of an ATTENTION, drains as the reading thread would. */
    private static final class ReaderDuringWrite implements Transport {
        private final Deque<Byte> incoming = new ArrayDeque<>();
        private TdsChannel channel;
        private Boolean drainedDuringWrite;
        private boolean failWrites;

        @Override
        public int read(ByteBuffer into) throws IOException {
            if (incoming.isEmpty()) {
                throw new IOException("the test server has nothing more to say");
            }
            int n = 0;
            while (into.hasRemaining() && !incoming.isEmpty()) {
                into.put(incoming.poll());
                n++;
            }
            return n;
        }

        @Override
        public int write(ByteBuffer from) throws IOException {
            if (failWrites) {
                throw new IOException("the connection is gone");
            }
            int n = from.remaining();
            if (from.get(from.position()) == Tds.TYPE_ATTENTION && drainedDuringWrite == null) {
                drainedDuringWrite = channel.drainAttention();
            }
            from.position(from.limit());
            return n;
        }

        @Override
        public boolean isOpen() {
            return true;
        }

        @Override
        public void close() {
        }
    }

    @Test
    void theReaderSeesTheAttentionWhileItIsBeingWritten() throws IOException {
        ReaderDuringWrite transport = new ReaderDuringWrite();
        TdsChannel channel = TdsChannel.over(transport);
        transport.channel = channel;
        for (byte b : acknowledgement()) {
            transport.incoming.add(b);
        }

        channel.sendAttention();

        assertTrue(transport.drainedDuringWrite,
                "while the ATTENTION was on its way, the reader was told nothing was owed");
        assertTrue(transport.incoming.isEmpty(), "the acknowledgement was read by the drain");
        assertFalse(channel.drainAttention(), "and it is owed once, not twice");
    }

    @Test
    void anAttentionThatCouldNotBeWrittenIsNotOwed() {
        ReaderDuringWrite transport = new ReaderDuringWrite();
        TdsChannel channel = TdsChannel.over(transport);
        transport.channel = channel;
        transport.failWrites = true;

        assertThrows(IOException.class, channel::sendAttention);

        // Nothing reached the server, so nothing will answer: owing it would
        // make the next statement wait for an acknowledgement that never comes.
        assertEquals(false, assertDoesNotRead(channel));
    }

    private static boolean assertDoesNotRead(TdsChannel channel) {
        try {
            return channel.drainAttention();
        } catch (IOException e) {
            throw new AssertionError("the drain tried to read an acknowledgement nobody owes", e);
        }
    }

    /** The server's acknowledgement: one message, a DONE with the attention bit. */
    private static byte[] acknowledgement() {
        byte[] done = {(byte) Tds.TOKEN_DONE, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        int length = Tds.HEADER_SIZE + done.length;
        ByteBuffer out = ByteBuffer.allocate(length);
        out.put((byte) Tds.TYPE_TABULAR_RESULT);
        out.put((byte) Tds.STATUS_END_OF_MESSAGE);
        out.put((byte) (length >>> 8));
        out.put((byte) length);
        out.putShort((short) 0);
        out.put((byte) 1);
        out.put((byte) 0);
        out.put(done);
        return out.array();
    }
}
