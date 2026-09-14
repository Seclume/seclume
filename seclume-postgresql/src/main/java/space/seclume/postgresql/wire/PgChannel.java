package space.seclume.postgresql.wire;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import space.seclume.internal.WireBuffer;

/**
 * The line to the server: messages in, messages out.
 *
 * <p>A PostgreSQL message is one byte of type tag, a 32-bit length (which
 * counts itself) and the content. The startup message is the only one without a
 * type tag - historically so, which is why it has a method of its own here.
 *
 * <p>Reading happens in blocks, not message by message: the receive buffer
 * takes in whatever is there right now, and the messages are read out of it
 * <b>in place</b>. A result with a thousand rows therefore costs a handful of
 * system calls instead of a thousand, and not a single copy.
 */
public final class PgChannel implements AutoCloseable {

    private static final int DEFAULT_BUFFER = 32 * 1024;

    private final SocketChannel channel;
    private final WireBuffer out = new WireBuffer(8 * 1024);
    private WireBuffer in = new WireBuffer(DEFAULT_BUFFER);

    /** Start of the length field of the message currently being written. */
    private int lengthAt = -1;
    /** End of the message read last, within the receive buffer. */
    private int messageEnd;

    private PgChannel(SocketChannel channel) {
        this.channel = channel;
    }

    public static PgChannel connect(String host, int port, int connectTimeoutMillis)
            throws IOException {
        SocketChannel channel = SocketChannel.open();
        try {
            channel.socket().connect(new InetSocketAddress(host, port), connectTimeoutMillis);
            channel.configureBlocking(true);
            // A handshake consists of small messages that have to leave at
            // once - with Nagle each one waits for the next.
            channel.setOption(StandardSocketOptions.TCP_NODELAY, Boolean.TRUE);
            return new PgChannel(channel);
        } catch (IOException e) {
            channel.close();
            throw e;
        }
    }

    /** For tests: an already connected channel. */
    public static PgChannel wrap(SocketChannel channel) {
        return new PgChannel(channel);
    }

    // ---- writing ---------------------------------------------------------

    /** Starts a message with a type tag. */
    public WireBuffer begin(byte tag) {
        out.putByte(tag);
        lengthAt = out.position();
        out.putInt(0);              // Platzhalter
        return out;
    }

    /** Starts the startup message, which has no type tag. */
    public WireBuffer beginUntagged() {
        lengthAt = out.position();
        out.putInt(0);
        return out;
    }

    /** Fills in the length afterwards and finishes the message. */
    public void end() {
        if (lengthAt < 0) {
            throw new IllegalStateException("no message was started");
        }
        out.putInt(lengthAt, out.position() - lengthAt);
        lengthAt = -1;
    }

    /**
     * Stops the receive buffer from being compacted.
     *
     * <p>While a result is being collected its rows are not copied anywhere -
     * the reader only writes down where each value <b>is</b>. Compacting would
     * shift the bytes and turn every one of those positions into a wrong
     * answer, so it waits until the result is complete.
     */
    public void keepBuffer(boolean on) {
        this.keeping = on;
    }

    /**
     * Hands the receive buffer over and takes another one in its place.
     *
     * <p>This is what makes a result set free of copies: the buffer that
     * already holds the rows becomes the buffer of the result, and the result
     * gives back the one it had. Nothing is allocated, nothing is copied - the
     * two swap places.
     *
     * @param replacement an empty buffer to read into from now on
     * @return the buffer holding the answer that was just read
     */
    public WireBuffer exchange(WireBuffer replacement) {
        int rest = filled - in.position();
        if (rest > 0) {
            // Bytes that already arrived and belong to nobody yet - they move
            // along, because the next message starts with them.
            replacement.clear();
            replacement.ensureCapacity(rest);
            java.lang.foreign.MemorySegment.copy(in.segment(), in.position(),
                    replacement.segment(), 0, rest);
        } else {
            replacement.clear();
        }
        WireBuffer handedOver = in;
        in = replacement;
        filled = Math.max(rest, 0);
        in.position(0);
        in.limit(filled);
        messageEnd = 0;
        return handedOver;
    }

    /** How many bytes are waiting to be sent - the brake for a pipeline. */
    public int pending() {
        return out.position();
    }

    /**
     * How often this connection has waited for an answer.
     *
     * <p>Counted here because this is the one place every request goes
     * through. See {@link space.seclume.RoundTrips} for what the
     * number is good for.
     */
    private long roundTrips;

    public long roundTrips() {
        return roundTrips;
    }

    /** Sends everything buffered and zeroes the send buffer. */
    public void flush() throws IOException {
        roundTrips++;
        ByteBuffer view = out.view();
        view.clear().position(0).limit(out.position());
        while (view.hasRemaining()) {
            channel.write(view);
        }
        // The send buffer was carrying the password a moment ago.
        out.clear();
    }

    // ---- reading ---------------------------------------------------------

    /**
     * Reads the next message.
     *
     * @return the type tag; afterwards the buffer stands on the content
     */
    public byte nextMessage() throws IOException {
        compactIfNeeded();
        fill(5);
        byte tag = in.getByte();
        int length = in.getInt();
        if (length < 4) {
            throw new IOException("the server announced a message of " + length + " bytes");
        }
        int payload = length - 4;
        fill(payload);
        messageEnd = in.position() + payload;
        // Set the limit to the end of the message: no reader can then run
        // into the next message by accident.
        in.limit(messageEnd);
        return tag;
    }

    /** The buffer of the message in flight. */
    public WireBuffer message() {
        return in;
    }

    /** How many bytes of the message in flight are still unread. */
    public int messageRemaining() {
        return messageEnd - in.position();
    }

    /** Skips the rest of the message in flight. */
    public void endMessage() {
        in.position(messageEnd);
        in.limit(filled);
    }

    // ---- buffer mechanics ------------------------------------------------

    /** The receive buffer is filled up to here. */
    private int filled;
    /** While true the receive buffer is not compacted - see keepBuffer. */
    private boolean keeping;

    private void fill(int needed) throws IOException {
        while (filled - in.position() < needed) {
            in.ensureCapacity(Math.max(filled + needed, in.capacity()));
            ByteBuffer view = in.view();
            view.clear().position(filled).limit(in.capacity());
            int read = channel.read(view);
            if (read < 0) {
                throw new IOException("the server closed the connection");
            }
            filled += read;
            in.limit(filled);
        }
        in.limit(filled);
    }

    /** Moves the unread remainder forward when the buffer threatens to fill up. */
    private void compactIfNeeded() {
        if (keeping) {
            // Somebody is recording positions in this buffer. Moving the bytes
            // now would move them out from under those positions.
            return;
        }
        int position = in.position();
        if (position == 0) {
            return;
        }
        int rest = filled - position;
        if (rest > 0 && position + 512 < in.capacity()) {
            return;    // es passt noch etwas hinein, kein Grund zu schieben
        }
        if (rest > 0) {
            java.lang.foreign.MemorySegment.copy(in.segment(), position, in.segment(), 0, rest);
        }
        // The area that became free may have held payload.
        in.segment().asSlice(rest, in.capacity() - rest).fill((byte) 0);
        in.position(0);
        filled = rest;
        in.limit(filled);
    }

    @Override
    public void close() {
        try {
            channel.close();
        } catch (IOException ignored) {
            // On close an error has no consequences.
        }
        out.close();
        in.close();
    }

    public boolean isOpen() {
        return channel.isOpen();
    }
}
