package space.seclume.sqlserver.tds;

import java.io.IOException;
import java.nio.ByteBuffer;

import space.seclume.internal.WireBuffer;

/**
 * The line to a SQL Server.
 *
 * <p>TDS splits a message into packets of a fixed size; the last one carries
 * {@link Tds#STATUS_END_OF_MESSAGE} in its status byte. This class reassembles
 * them while reading, so the layers above deal in messages rather than packets.
 *
 * <p>The buffers live in native memory - the login packet with the obfuscated
 * password passes through the send buffer, which is zeroed afterwards.
 */
public final class TdsChannel implements AutoCloseable {

    private final space.seclume.internal.Transport channel;
    private final WireBuffer out = new WireBuffer(16 * 1024);
    private final WireBuffer in = new WireBuffer(32 * 1024);

    private int packetSize = Tds.DEFAULT_PACKET_SIZE;
    private int packetId = 1;
    /** The reassembled message is filled up to here. */
    private int messageLength;
    private int messageType;
    private int filled;
    /**
     * From the handshake onwards everything runs through this. Before that it
     * is {@code null} - and during the handshake the nesting is the other way
     * round, TLS records inside TDS packets, which {@link TdsTls} handles.
     */
    private space.seclume.internal.TlsLayer tls;

    private TdsChannel(space.seclume.internal.Transport channel) {
        this.channel = channel;
    }

    public static TdsChannel connect(String host, int port, int connectTimeoutMillis)
            throws IOException {
        return connect(host, port, connectTimeoutMillis, null);
    }

    /**
     * The same, with a say in which transport carries it.
     *
     * @param transport {@code socket}, {@code ffm}, {@code ffm-if-available},
     *                  or null to take what the system property says
     */
    public static TdsChannel connect(String host, int port, int connectTimeoutMillis,
            String transport) throws IOException {
        // Blocking and TCP_NODELAY live in the transport now - they belong to
        // whoever owns the descriptor, not to whoever frames packets in it.
        return new TdsChannel(space.seclume.internal.Transports.open(transport, host, port, connectTimeoutMillis));
    }

    /** The raw channel - only for the TLS handshake, which frames its own packets. */
    space.seclume.internal.Transport raw() {
        return channel;
    }

    /**
     * Switches to TLS.
     *
     * <p>From here on the TDS packets sit inside TLS records; before, it was
     * the other way round. The caller has already run the handshake.
     */
    public void useTls(space.seclume.internal.TlsLayer layer) {
        this.tls = layer;
    }

    public boolean isEncrypted() {
        return tls != null;
    }

    /** What TLS this connection uses, or {@code null} without it. */
    public String tlsDescription() {
        return tls == null ? null : tls.description();
    }

    // ---- writing ---------------------------------------------------------

    /** Starts a message; the header is filled in when it is sent. */
    public WireBuffer begin() {
        out.rewind();
        out.putZeroes(Tds.HEADER_SIZE);
        return out;
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

    /**
     * Sends the message.
     *
     * <p>If it does not fit into one packet it is split: every piece gets its
     * own header, and only the last one carries the end bit. The server
     * reassembles it the same way.
     */
    public void send(int type) throws IOException {
        roundTrips++;
        int payloadLength = out.position() - Tds.HEADER_SIZE;
        int maxPayload = packetSize - Tds.HEADER_SIZE;
        if (payloadLength <= maxPayload) {
            writeHeader(0, type, Tds.STATUS_END_OF_MESSAGE, Tds.HEADER_SIZE + payloadLength);
            flush(Tds.HEADER_SIZE + payloadLength);
            return;
        }
        // Split it: the content is already in the buffer, so send it in pieces.
        int sent = 0;
        while (sent < payloadLength) {
            int chunk = Math.min(maxPayload, payloadLength - sent);
            boolean last = sent + chunk >= payloadLength;
            WireBuffer piece = new WireBuffer(Tds.HEADER_SIZE + chunk);
            try {
                piece.putZeroes(Tds.HEADER_SIZE);
                piece.putBytes(out.segment(), Tds.HEADER_SIZE + sent, chunk);
                piece.putUnsignedLeAt(0, type, 1);
                piece.putByteAt(1, (byte) (last ? Tds.STATUS_END_OF_MESSAGE : 0));
                piece.putByteAt(2, (byte) ((Tds.HEADER_SIZE + chunk) >>> 8));
                piece.putByteAt(3, (byte) (Tds.HEADER_SIZE + chunk));
                piece.putByteAt(6, (byte) packetId++);
                ByteBuffer view = piece.view();
                view.clear().position(0).limit(Tds.HEADER_SIZE + chunk);
                write(view);
            } finally {
                piece.close();
            }
            sent += chunk;
        }
        out.clear();
        packetId = 1;
    }

    private void writeHeader(int at, int type, int status, int length) {
        out.putByteAt(at, (byte) type);
        out.putByteAt(at + 1, (byte) status);
        // The length is big-endian - the only field in all of TDS that is.
        out.putByteAt(at + 2, (byte) (length >>> 8));
        out.putByteAt(at + 3, (byte) length);
        out.putByteAt(at + 4, (byte) 0);
        out.putByteAt(at + 5, (byte) 0);
        out.putByteAt(at + 6, (byte) 1);
        out.putByteAt(at + 7, (byte) 0);
    }

    /**
     * Writes bytes out - through TLS once the handshake is done.
     *
     * <p>Everything that leaves has to go through here. A second path that
     * writes to the socket directly would send unencrypted TDS into an
     * encrypted connection, and the server answers that by hanging up - which
     * looks like a network fault and is none.
     */
    private void write(ByteBuffer view) throws IOException {
        if (tls != null) {
            tls.write(view);
            return;
        }
        while (view.hasRemaining()) {
            channel.write(view);
        }
    }

    private void flush(int length) throws IOException {
        ByteBuffer view = out.view();
        view.clear().position(0).limit(length);
        write(view);
        // The send buffer carried the login packet.
        out.clear();
        packetId = 1;
    }

    // ---- reading ---------------------------------------------------------

    /**
     * Reads one complete message, across however many packets it takes.
     *
     * @return the message type; the buffer then stands at the content
     */
    public int receive() throws IOException {
        in.rewind();
        // TDS is strictly alternating: one request, one answer. That is why the
        // receive buffer may start at zero for each message - nothing unread
        // from an earlier answer can be sitting in it.
        filled = 0;
        messageLength = 0;
        boolean last = false;
        while (!last) {
            int headerAt = messageLength;
            fillTo(headerAt + Tds.HEADER_SIZE);
            messageType = in.getByte(headerAt) & 0xff;
            int status = in.getByte(headerAt + 1) & 0xff;
            int length = ((in.getByte(headerAt + 2) & 0xff) << 8)
                    | (in.getByte(headerAt + 3) & 0xff);
            if (length < Tds.HEADER_SIZE) {
                throw new IOException("the server announced a packet of " + length + " bytes");
            }
            fillTo(headerAt + length);
            last = (status & Tds.STATUS_END_OF_MESSAGE) != 0;

            // Cut the header out of the reassembled message. Everything behind
            // it moves too, not just this packet's payload: the socket may
            // already have delivered part of the next packet, and if that were
            // left where it is, the next header would be read eight bytes off.
            // A message that fits into one packet never notices - which is why
            // this only showed up against a real server.
            int payload = length - Tds.HEADER_SIZE;
            int behind = filled - (headerAt + Tds.HEADER_SIZE);
            java.lang.foreign.MemorySegment.copy(in.segment(), headerAt + Tds.HEADER_SIZE,
                    in.segment(), headerAt, behind);
            filled -= Tds.HEADER_SIZE;
            messageLength = headerAt + payload;
        }
        in.position(0);
        in.limit(messageLength);
        return messageType;
    }

    /** How many bytes the reassembled message has. */
    public int messageLength() {
        return messageLength;
    }

    /** The buffer of the current message. */
    public WireBuffer message() {
        return in;
    }

    private void fillTo(int needed) throws IOException {
        while (filled < needed) {
            in.ensureCapacity(Math.max(needed, in.capacity()));
            ByteBuffer view = in.view();
            view.clear().position(filled).limit(in.capacity());
            int read = tls != null ? tls.read(view) : channel.read(view);
            if (read < 0) {
                throw new IOException("the server closed the connection");
            }
            filled += read;
        }
        in.limit(filled);
    }

    /** The packet size the server has settled on. */
    public void packetSize(int size) {
        this.packetSize = Math.max(512, size);
    }

    public int packetSize() {
        return packetSize;
    }

    public boolean isOpen() {
        return channel.isOpen();
    }

    @Override
    public void close() {
        // The transport swallows its own close error - see Transport#close.
        channel.close();
        out.close();
        in.close();
    }
}
