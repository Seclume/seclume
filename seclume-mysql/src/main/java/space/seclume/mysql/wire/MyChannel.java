package space.seclume.mysql.wire;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import space.seclume.internal.WireBuffer;

/**
 * The line to a MySQL or MariaDB server.
 *
 * <p>A MySQL packet is a 3-byte length (little-endian, not counting the header)
 * and a sequence number. The sequence number is the real difference from
 * PostgreSQL: it counts up within one command, starts at 0 again with every new
 * command, and the server checks it. Get it wrong and you get "Got packets out
 * of order" - which is why it is managed in exactly one place here and not
 * passed through by the callers.
 *
 * <p>A packet can only carry {@code 0xffffff} bytes. Larger payloads are cut
 * into pieces of that size, and a piece of exactly {@code 0xffffff} bytes
 * means: more is coming. An empty packet at the end belongs to that when the
 * payload is an exact multiple.
 *
 * <p>Reading happens in blocks, and the packets are evaluated <b>in place</b> -
 * no copying per row.
 */
public final class MyChannel implements AutoCloseable {

    private static final int DEFAULT_BUFFER = 32 * 1024;
    private static final int HEADER = 4;

    private final SocketChannel channel;
    private final WireBuffer out = new WireBuffer(8 * 1024);
    private final WireBuffer in = new WireBuffer(DEFAULT_BUFFER);

    /** Sequence number of the next packet - the server checks it. */
    private int sequence;
    /** Start of the packet header currently being written. */
    private int headerAt = -1;
    private int messageEnd;
    private int filled;

    private MyChannel(SocketChannel channel) {
        this.channel = channel;
    }

    public static MyChannel connect(String host, int port, int connectTimeoutMillis)
            throws IOException {
        SocketChannel channel = SocketChannel.open();
        try {
            channel.socket().connect(new InetSocketAddress(host, port), connectTimeoutMillis);
            channel.configureBlocking(true);
            channel.setOption(StandardSocketOptions.TCP_NODELAY, Boolean.TRUE);
            return new MyChannel(channel);
        } catch (IOException e) {
            channel.close();
            throw e;
        }
    }

    /** For tests: an already connected channel. */
    public static MyChannel wrap(SocketChannel channel) {
        return new MyChannel(channel);
    }

    // ---- writing ---------------------------------------------------------

    /**
     * Starts a command: the sequence number begins at 0 again, and the first
     * byte of the payload is the command tag.
     */
    public WireBuffer beginCommand(byte command) {
        sequence = 0;
        WireBuffer buffer = beginPacket();
        buffer.putByte(command);
        return buffer;
    }

    /** How many bytes are waiting to be sent - the brake for a pipeline. */
    public int pending() {
        return out.position();
    }

    /** Starts a packet continuing the running sequence number. */
    public WireBuffer beginPacket() {
        headerAt = out.position();
        out.putZeroes(HEADER);
        return out;
    }

    /** Fills in length and sequence number afterwards. */
    public void end() {
        if (headerAt < 0) {
            throw new IllegalStateException("no packet was started");
        }
        int payload = out.position() - headerAt - HEADER;
        if (payload > MyPackets.MAX_PAYLOAD) {
            throw new IllegalStateException(
                    "a single packet cannot carry " + payload + " bytes - split it");
        }
        out.putUnsignedLeAt(headerAt, payload, 3);
        out.putByteAt(headerAt + 3, (byte) (sequence & 0xff));
        sequence++;
        headerAt = -1;
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

    /** Zeroes the send buffer - after the login the password was in it. */
    public void clearSendBuffer() {
        out.clear();
    }

    /** Sets the sequence number the way the handshake requires. */
    public void sequence(int next) {
        this.sequence = next;
    }

    public int sequence() {
        return sequence;
    }

    // ---- reading ---------------------------------------------------------

    /**
     * Reads the next packet.
     *
     * <p>Afterwards the buffer stands on the first byte of the payload, and the
     * limit lies at the end of the packet - a reader cannot run into the next
     * packet by accident.
     *
     * @return the first byte of the payload, without consuming it
     */
    public int nextPacket() throws IOException {
        compactIfNeeded();
        fill(HEADER);
        int length = (int) in.getUnsignedLe(3);
        sequence = (in.getByte() & 0xff) + 1;
        fill(length);
        messageEnd = in.position() + length;
        in.limit(messageEnd);
        if (length == MyPackets.MAX_PAYLOAD) {
            // A full packet means: the payload continues in the next one.
            // That happens with very large rows; reassembling it does not
            // happen here yet.
            throw new IOException(
                    "the server sent a payload split across packets - seclume does not "
                    + "reassemble split payloads yet (see docs/protocol/mysql.md)");
        }
        return length == 0 ? -1 : (in.getByte(in.position()) & 0xff);
    }

    /** The buffer of the packet in flight. */
    public WireBuffer packet() {
        return in;
    }

    public int packetRemaining() {
        return messageEnd - in.position();
    }

    /** Skips the rest of the packet in flight. */
    public void endPacket() {
        in.position(messageEnd);
        in.limit(filled);
    }

    // ---- buffer mechanics ------------------------------------------------

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

    private void compactIfNeeded() {
        int position = in.position();
        if (position == 0) {
            return;
        }
        int rest = filled - position;
        if (rest > 0 && position + 512 < in.capacity()) {
            return;
        }
        if (rest > 0) {
            java.lang.foreign.MemorySegment.copy(in.segment(), position, in.segment(), 0, rest);
        }
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
