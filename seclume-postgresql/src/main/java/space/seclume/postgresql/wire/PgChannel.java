package space.seclume.postgresql.wire;

import java.io.IOException;
import java.nio.ByteBuffer;

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

    /**
     * Not final: a session outlives its socket when a connection is moved.
     * See {@link #replaceTransport}.
     */
    private space.seclume.internal.Transport channel;

    /**
     * The TLS layer once the server agreed to it, or {@code null}.
     *
     * <p>PostgreSQL switches the whole connection over after a negotiation of
     * nine bytes in the clear: from then on every message travels inside TLS
     * records, and the two places that touch the socket are the only ones that
     * have to know.
     */
    private space.seclume.internal.TlsChannel tls;
    private final WireBuffer out = new WireBuffer(8 * 1024);
    private WireBuffer in = new WireBuffer(DEFAULT_BUFFER);

    /** Start of the length field of the message currently being written. */
    private int lengthAt = -1;
    /** End of the message read last, within the receive buffer. */
    private int messageEnd;

    private PgChannel(space.seclume.internal.Transport channel) {
        this.channel = channel;
    }

    public static PgChannel connect(String host, int port, int connectTimeoutMillis)
            throws IOException {
        return connect(host, port, connectTimeoutMillis, null);
    }

    /**
     * The same, with a say in which transport carries it.
     *
     * <p>The socket options that used to stand here - blocking, TCP_NODELAY -
     * live in the transport now, because they belong to whoever owns the
     * descriptor and not to whoever writes messages into it.
     *
     * @param transport {@code socket}, {@code ffm}, {@code ffm-if-available},
     *                  or null to take what the system property says
     */
    public static PgChannel connect(String host, int port, int connectTimeoutMillis,
            String transport) throws IOException {
        return new PgChannel(space.seclume.internal.Transports.open(
                transport, host, port, connectTimeoutMillis));
    }

    /**
     * Asks the server for TLS and reads its one-byte answer.
     *
     * <p>The message is eight bytes and has no type tag: a length of 8 and the
     * number 80877103, which is not a protocol version but a marker chosen so
     * that no real version can collide with it. The answer is a single byte —
     * {@code S} yes, {@code N} no — and nothing else; only after a yes does
     * anything look like TLS on this socket.
     *
     * @return whether the server agreed
     */
    public boolean requestTls() throws IOException {
        out.clear();
        out.putInt(8);
        out.putInt(80877103);
        ByteBuffer request = out.view();
        request.clear().position(0).limit(out.position());
        while (request.hasRemaining()) {
            channel.write(request);
        }
        out.clear();

        ByteBuffer answer = ByteBuffer.allocateDirect(1);
        while (answer.hasRemaining()) {
            if (channel.read(answer) < 0) {
                throw new IOException("the server closed the connection while asked for TLS");
            }
        }
        answer.flip();
        byte reply = answer.get();
        if (reply == 'S') {
            return true;
        }
        if (reply == 'N') {
            return false;
        }
        // An 'E' would be an error message in the old format; anything else is
        // not a PostgreSQL server. Either way, guessing on would be worse.
        throw new IOException("the server answered the TLS request with 0x"
                + Integer.toHexString(reply & 0xff) + ", which is neither yes nor no");
    }

    /**
     * Switches the connection to TLS. The server has already agreed at this
     * point; what follows is the ordinary handshake.
     */
    public void startTls(String host, int port, boolean verify) throws IOException {
        space.seclume.internal.TlsChannel started =
                space.seclume.internal.TlsChannel.create(channel, host, port, verify);
        started.handshake();
        this.tls = started;
    }

    /** The server's certificate, or {@code null} without TLS - for channel binding. */
    public java.security.cert.X509Certificate peerCertificate() throws IOException {
        return tls == null ? null : tls.peerCertificate();
    }

    /** What TLS is in use, for the preflight report; {@code null} without it. */
    public String tlsDescription() {
        return tls == null ? null : tls.protocol() + " / " + tls.cipherSuite();
    }

    /**
     * For tests: a channel over any transport at all.
     *
     * <p>The one that proves the seam is real. A test that only ever passes a
     * SocketChannel through it would pass just as well if something below
     * still cast back to one.
     */
    public static PgChannel over(space.seclume.internal.Transport transport) {
        return new PgChannel(transport);
    }

    /** For tests: an already connected channel. */
    public static PgChannel wrap(java.nio.channels.SocketChannel channel) {
        return new PgChannel(space.seclume.internal.SocketTransport.wrap(channel));
    }

    // ---- writing ---------------------------------------------------------

    /** Starts a message with a type tag. */
    public WireBuffer begin(byte tag) {
        out.putByte(tag);
        lengthAt = out.position();
        out.putInt(0);              // a placeholder
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
        if (tls != null) {
            tls.write(view);
        } else {
            while (view.hasRemaining()) {
                channel.write(view);
            }
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
            int read = tls != null ? tls.read(view) : channel.read(view);
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
            return;    // there is still room, no reason to move anything
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


    // ---- moving the connection underneath ---------------------------------

    /** Whether this channel runs inside TLS. */
    public boolean isEncrypted() {
        return tls != null;
    }

    /** The transport carrying this channel - for whoever has to freeze it. */
    public space.seclume.internal.Transport transport() {
        return channel;
    }

    /**
     * Whether the channel has nothing of its own in flight.
     *
     * <p>Nothing written and not yet flushed, nothing received and not yet
     * read, and no row window pinning the buffer. This is the protocol half of
     * the quiescent point; the TCP half is the two empty queues, and both have
     * to hold before a connection may be taken apart.
     */
    public boolean isIdle() {
        return out.position() == 0 && in.position() == filled && !keeping;
    }

    /**
     * Puts a different transport underneath, keeping every buffer as it is.
     *
     * <p>That is the whole trick of a move within one process: the protocol
     * state, the prepared plans, the TLS engine and the two buffers are all
     * objects that never noticed anything. Only the descriptor changed.
     *
     * <p>The old transport is <b>not</b> closed here. Closing it while the
     * server may still retransmit is what answers that retransmission with an
     * RST. The caller closes it once the new one has taken over.
     */
    public void replaceTransport(space.seclume.internal.Transport replacement)
            throws IOException {
        if (!isIdle()) {
            throw new IOException("this channel has work in flight - "
                    + out.position() + " bytes unsent, "
                    + (filled - in.position()) + " unread"
                    + (keeping ? ", and a row window is holding the buffer" : ""));
        }
        this.channel = replacement;
        if (tls != null) {
            // The TLS layer holds its own reference and would otherwise keep
            // reading through the closed descriptor.
            tls.replaceTransport(replacement);
        }
    }

    @Override
    public void close() {
        // The transport swallows its own close error - see Transport#close.
        channel.close();
        out.close();
        in.close();
    }

    public boolean isOpen() {
        return channel.isOpen();
    }
}
