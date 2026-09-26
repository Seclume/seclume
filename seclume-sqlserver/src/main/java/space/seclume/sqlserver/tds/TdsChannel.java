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

    private space.seclume.internal.Transport channel;
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
    /**
     * How many ATTENTIONs were written whose acknowledgement is still unread.
     *
     * <p>A count and not a flag, and the difference is a real failure: two
     * cancellations in a row put two acknowledgements on the wire, and a
     * client that drains one finds the other at the head of the next
     * statement's answer. A query-timeout thread that fires twice is not
     * exotic.
     *
     * <p>Atomic because it is raised on the thread that cancels and cleared on
     * the thread doing the work.
     */
    private final java.util.concurrent.atomic.AtomicInteger attentionsPending =
            new java.util.concurrent.atomic.AtomicInteger();

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

    /** A channel on a transport somebody else opened - see TdsSession#resume. */
    public static TdsChannel over(space.seclume.internal.Transport transport) {
        return new TdsChannel(transport);
    }

    /**
     * A channel over a stream that already has a TLS layer on it.
     *
     * <p>The counterpart to {@link #tlsLayer()}: the stream was handed on
     * while encrypted, and the encryption goes with it. The server is told
     * nothing and notices nothing - the same TLS connection simply carries
     * on, which is why the session on it survives.
     */
    public static TdsChannel over(space.seclume.internal.Transport transport,
            space.seclume.internal.TlsLayer tls) {
        TdsChannel channel = new TdsChannel(transport);
        channel.tls = tls;
        return channel;
    }

    /**
     * Whether the encryption on this channel - if any - could be handed on
     * with the stream.
     *
     * <p>True without TLS, because there is nothing to carry; true on
     * seclume's own TLS stack, because its state is ours; false on the JDK's,
     * because an {@code SSLEngine} will not give its keys up. See
     * {@link space.seclume.internal.TlsLayer#movable()}.
     */
    public boolean encryptionCanTravel() {
        return tls == null || tls.movable();
    }

    /**
     * The encryption on this channel, or {@code null} without TLS - for
     * whoever continues the stream.
     *
     * <p>Handed out rather than described, and that is the whole of what this
     * library does about it. What a caller then does with the layer - take it
     * straight to another session, or write its state down and take it up
     * somewhere else with {@code freeze} and {@code thaw} - is the caller's
     * business and not a driver's.
     */
    public space.seclume.internal.TlsLayer tlsLayer() {
        return tls;
    }

    /** The transport carrying this channel - for whoever has to hand it on. */
    public space.seclume.internal.Transport transport() {
        return channel;
    }

    /**
     * Whether nothing is half-written on this side.
     *
     * <p>Only half the question, and in TDS the other half is not the
     * channel's to answer. The receive buffer holds <b>one message</b> and is
     * reset at the start of the next - so bytes left unread in it are not work
     * in flight but a tail the caller chose to skip, which a login response
     * routinely has. Nothing of them is still on the socket.
     *
     * <p>What cannot be seen from here is whether the caller is in the middle
     * of a result it means to go on reading. That is the session's state, and
     * {@code TdsSession#detach} asks it there.
     */
    public boolean isIdle() {
        return out.position() == 0;
    }

    /** What is in flight, for an error message that can be acted on. */
    public String inFlight() {
        return out.position() + " bytes unsent, " + (messageLength - in.position())
                + " of the last message unread";
    }

    /** Puts another transport under this channel; the old one is not closed. */
    public void replaceTransport(space.seclume.internal.Transport replacement)
            throws java.io.IOException {
        if (!isIdle()) {
            throw new java.io.IOException("this channel has work in flight");
        }
        this.channel = replacement;
        if (tls != null) {
            tls.replaceTransport(replacement);
        }
    }

    /** Gives the channel up without closing the transport - see TdsSession#detach. */
    public void release() {
        release(false);
    }

    /**
     * The same, with a say over the encryption.
     *
     * <p>{@code keepEncryption} is for the one case where the TLS layer goes
     * with the stream rather than staying behind: discarding it here would
     * free the very keys the successor is about to read records with.
     */
    public void release(boolean keepEncryption) {
        if (released) {
            return;
        }
        released = true;
        if (tls != null && !keepEncryption) {
            tls.discard();
        }
        out.close();
        in.close();
    }

    private boolean released;

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
     * The message being written, for a caller adding to one it started.
     *
     * <p>Deliberately not {@link #begin()}: that one rewinds, which is right
     * for a new message and would silently drop a half-written one. A caller
     * that puts several RPCs into one message needs the second of them to
     * continue rather than to restart.
     */
    public WireBuffer buffer() {
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
     * The flight recorder, or {@code null} when nobody asked for one.
     *
     * <p>See {@link space.seclume.Flight}.
     */
    private space.seclume.internal.FlightRecorder flight;

    /** Switches the recording on - see {@link space.seclume.Flight}. */
    public void recordFlight(space.seclume.internal.FlightRecorder recorder) {
        this.flight = recorder;
    }

    /** What this connection last sent and received, oldest first. */
    public java.util.List<space.seclume.Flight.Message> recentMessages() {
        return flight == null ? java.util.List.of() : flight.recent();
    }

    /** How many messages have crossed this connection. */
    public long recordedMessages() {
        return flight == null ? 0 : flight.messages();
    }

    /** The tail of the recording, or {@code null} when there is none. */
    public String flightTail() {
        return flight == null ? null : flight.tail(8);
    }

    /**
     * The name of a TDS message type, for a diagnostic.
     *
     * <p><b>And the withholding question, answered differently here.</b> A
     * LOGIN7 packet carries the password, obfuscated by a XOR that is not
     * encryption - so its length is the password's length plus the fixed
     * fields, exactly the case PostgreSQL's cleartext path has. That it also
     * travels inside TLS protects it on the wire and not in a ring buffer in
     * this process, which is what this recorder is. So the count is withheld.
     */
    private static String nameOf(int type) {
        return switch (type) {
            case Tds.TYPE_SQL_BATCH -> "SQLBatch";
            case Tds.TYPE_RPC -> "RPC";
            case Tds.TYPE_TABULAR_RESULT -> "TabularResult";
            case Tds.TYPE_ATTENTION -> "Attention";
            case Tds.TYPE_TRANSACTION_MANAGER -> "TransactionManager";
            case Tds.TYPE_LOGIN7 -> "LOGIN7";
            case Tds.TYPE_PRELOGIN -> "PreLogin";
            default -> "0x" + Integer.toHexString(type);
        };
    }

    /**
     * Sends the message.
     *
     * <p>If it does not fit into one packet it is split: every piece gets its
     * own header, and only the last one carries the end bit. The server
     * reassembles it the same way.
     */
    public void send(int type) throws IOException {
        if (!partial) {
            // Before the request, not after: an ATTENTION sent while nothing
            // was running has an acknowledgement sitting on the wire, and it
            // must not be read as the beginning of this statement's answer.
            drainAttention();
            roundTrips++;
        }
        int payloadLength = out.position() - Tds.HEADER_SIZE;
        if (flight != null) {
            flight.record(true, nameOf(type),
                    type == Tds.TYPE_LOGIN7 ? space.seclume.Flight.WITHHELD
                            : (int) Math.min(Integer.MAX_VALUE,
                                    sentBefore + payloadLength + Tds.HEADER_SIZE));
        }
        partial = false;
        sentBefore = 0;
        int maxPayload = packetSize - Tds.HEADER_SIZE;
        // In place: each packet's header goes over the last eight bytes of
        // the one before, which have left already. The pieces used to be
        // copied into a buffer of their own, a native allocation and a free
        // per packet.
        int sent = 0;
        while (true) {
            int chunk = Math.min(maxPayload, payloadLength - sent);
            boolean last = sent + chunk >= payloadLength;
            writeHeader(sent, type, last ? Tds.STATUS_END_OF_MESSAGE : 0,
                    Tds.HEADER_SIZE + chunk);
            ByteBuffer view = out.view();
            view.clear().position(sent).limit(sent + Tds.HEADER_SIZE + chunk);
            write(view);
            sent += chunk;
            if (last) {
                break;
            }
        }
        out.clear();
        packetId = 1;
    }

    /** Whether packets of the message being written have gone out already. */
    private boolean partial;
    /** How many payload bytes of it, for the recording. */
    private long sentBefore;

    /**
     * Sends the full packets of a message that is still being written, and
     * keeps the rest to go on from.
     *
     * <p>A batch of five thousand rows is a megabyte. Written whole and then
     * sent, the server sat idle while it was encoded and the client while the
     * server ran it; sent as the packets fill, the server runs the first rows
     * while the last are still being written - the way mssql-jdbc sends.
     */
    public void sendFull(int type) throws IOException {
        int maxPayload = packetSize - Tds.HEADER_SIZE;
        int payload = out.position() - Tds.HEADER_SIZE;
        if (payload <= maxPayload) {
            return;                                  // the last packet is never sent here
        }
        if (!partial) {
            drainAttention();
            roundTrips++;
            partial = true;
        }
        int sent = 0;
        while (payload - sent > maxPayload) {
            writeHeader(sent, type, 0, packetSize);
            ByteBuffer view = out.view();
            view.clear().position(sent).limit(sent + packetSize);
            write(view);
            sent += maxPayload;
        }
        int rest = payload - sent;
        java.lang.foreign.MemorySegment.copy(out.segment(), Tds.HEADER_SIZE + sent,
                out.segment(), Tds.HEADER_SIZE, rest);
        out.position(Tds.HEADER_SIZE + rest);
        sentBefore += sent;
    }

    /**
     * Asks the server to reset the session before the next request: the
     * RESETCONNECTION bit on that request's first packet, which is what
     * {@code sp_reset_connection} is on the wire - no round trip of its own.
     */
    public void resetBeforeNextRequest() {
        resetNext = true;
    }

    private boolean resetNext;

    private void writeHeader(int at, int type, int status, int length) {
        if (resetNext) {
            status |= 0x08;                      // RESETCONNECTION
            resetNext = false;
        }
        out.putByteAt(at, (byte) type);
        out.putByteAt(at + 1, (byte) status);
        // The length is big-endian - the only field in all of TDS that is.
        out.putByteAt(at + 2, (byte) (length >>> 8));
        out.putByteAt(at + 3, (byte) length);
        out.putByteAt(at + 4, (byte) 0);
        out.putByteAt(at + 5, (byte) 0);
        out.putByteAt(at + 6, (byte) packetId++);
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

    /**
     * Tells the server to stop what it is doing, on this same connection.
     *
     * <p>TDS has no second channel for this and does not need one: an
     * ATTENTION is a bare header - eight bytes, type 6, end of message - and
     * it is written while the reader is still blocked waiting for the answer
     * it is about to interrupt. A socket is full duplex, so a write in one
     * direction does not wait for a read in the other.
     *
     * <p><b>Its own buffer, not {@link #begin()}'s.</b> The send buffer
     * belongs to whichever thread wrote the request; this method is called
     * from a different one, by definition, and writing an ATTENTION into a
     * buffer another thread is holding would corrupt whatever is in it. Eight
     * bytes on their own cost nothing.
     *
     * <p>The server answers by finishing the message it was in the middle of -
     * possibly with rows already in it - and setting
     * {@link TokenStream#DONE_ATTENTION} in the closing DONE. There is no
     * separate acknowledgement, which is why that bit is the only evidence a
     * cancellation happened at all.
     */
    public void sendAttention() throws IOException {
        WireBuffer attention = new WireBuffer(Tds.HEADER_SIZE);
        attention.putZeroes(Tds.HEADER_SIZE);
        attention.putByteAt(0, (byte) Tds.TYPE_ATTENTION);
        attention.putByteAt(1, (byte) Tds.STATUS_END_OF_MESSAGE);
        attention.putByteAt(2, (byte) (Tds.HEADER_SIZE >>> 8));
        attention.putByteAt(3, (byte) Tds.HEADER_SIZE);
        attention.putByteAt(6, (byte) 1);
        ByteBuffer view = attention.view();
        view.clear().position(0).limit(Tds.HEADER_SIZE);
        write(view);
        attentionsPending.incrementAndGet();
    }

    /**
     * Reads the acknowledgement an ATTENTION always gets, and throws it away.
     *
     * <p><b>This is the part that is easy to leave out, and it breaks the
     * connection rather than the cancellation.</b> The server answers an
     * ATTENTION with a message of its own - measured against a real SQL
     * Server: the interrupted batch closes with a DONE carrying the error bit,
     * and the acknowledgement follows as a <b>separate</b> message. A client
     * that does not read it finds it at the head of the next statement's
     * answer, and from then on it is one message behind for good.
     *
     * <p>So it is drained in two places: after an answer, where the statement
     * that was interrupted is waiting to be told; and before the next request,
     * for the cancellation that arrived when nothing was running - which is
     * what a query-timeout thread does every time the query finishes first.
     *
     * @return whether there was one to drain
     */
    public boolean drainAttention() throws IOException {
        int owed = attentionsPending.getAndSet(0);
        for (int i = 0; i < owed; i++) {
            receive();
        }
        return owed > 0;
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
        // The previous answer is still lying here: rewinding moves the
        // pointers and not the memory, so a long result followed by a short
        // one left most of the long one in native memory indefinitely. It is
        // rows rather than credentials, which is precisely what one does not
        // want in a core dump - and the heap dump harness cannot see this
        // buffer at all, so nothing else would have caught it.
        if (filled > 0) {
            in.segment().asSlice(0, Math.min(filled, in.capacity())).fill((byte) 0);
        }
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
        if (flight != null) {
            // One entry per reassembled message, not per packet: a large
            // answer arrives in many packets and a recording that showed them
            // all would bury the order in a list of identical lines.
            flight.record(false, nameOf(messageType), messageLength);
        }
        return messageType;
    }

    /** Takes what has arrived of a message; see {@link #receiveStreaming}. */
    @FunctionalInterface
    public interface Consumer {
        /**
         * @param in  the message so far, from offset 0
         * @param end how many bytes of it are there
         * @return how many bytes from the start were used up and may go
         */
        int take(WireBuffer in, int end) throws IOException, java.sql.SQLException;
    }

    /**
     * Reads one message, handing it on packet by packet.
     *
     * <p>{@link #receive} waits for the last packet before anybody looks at
     * the first, so a large result was read in two phases: the network, then
     * the rows, one after the other. Here the consumer takes what has come
     * after every packet, while the kernel is already receiving the next one,
     * and what it has used up leaves the buffer - which then holds a packet
     * or two instead of the whole answer.
     *
     * @return the message type
     */
    public int receiveStreaming(Consumer consumer) throws IOException, java.sql.SQLException {
        startStreaming();
        pump(consumer, null);
        return messageType;
    }

    /** Whether the last packet of the message being streamed has arrived. */
    private boolean lastSeen;
    /** How many bytes of it have been used up so far. */
    private long streamed;

    /** Begins a message that {@link #pump} then reads. */
    public void startStreaming() {
        if (filled > 0) {
            in.segment().asSlice(0, Math.min(filled, in.capacity())).fill((byte) 0);
        }
        in.rewind();
        filled = 0;
        messageLength = 0;
        streamed = 0;
        lastSeen = false;
    }

    /**
     * Reads packets and hands them on, until the message ends - or until
     * {@code pause} says enough, after a packet: then the rest stays on the
     * wire, and the next call goes on where this one stopped.
     *
     * @param pause asked after every packet; {@code null} reads to the end
     * @return whether the message is complete
     */
    public boolean pump(Consumer consumer, java.util.function.BooleanSupplier pause)
            throws IOException, java.sql.SQLException {
        while (!lastSeen) {
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
            lastSeen = (status & Tds.STATUS_END_OF_MESSAGE) != 0;
            int payload = length - Tds.HEADER_SIZE;
            int behind = filled - (headerAt + Tds.HEADER_SIZE);
            java.lang.foreign.MemorySegment.copy(in.segment(), headerAt + Tds.HEADER_SIZE,
                    in.segment(), headerAt, behind);
            filled -= Tds.HEADER_SIZE;
            messageLength = headerAt + payload;

            in.position(0);
            in.limit(messageLength);
            int used = consumer.take(in, messageLength);
            if (lastSeen && used != messageLength) {
                throw new IOException("the answer ends in the middle of a token, "
                        + (messageLength - used) + " bytes before its end");
            }
            if (used > 0) {
                // What was used goes: the rest of the message, and whatever of
                // the next packet the socket already delivered, moves to the
                // front, and the bytes it leaves behind are cleared - they
                // were rows.
                java.lang.foreign.MemorySegment.copy(in.segment(), used, in.segment(), 0,
                        filled - used);
                in.segment().asSlice(filled - used, used).fill((byte) 0);
                filled -= used;
                messageLength -= used;
                streamed += used;
            }
            if (!lastSeen && pause != null && pause.getAsBoolean()) {
                return false;
            }
        }
        in.position(0);
        in.limit(messageLength);
        if (flight != null) {
            flight.record(false, nameOf(messageType), (int) Math.min(streamed, Integer.MAX_VALUE));
        }
        return true;
    }

    /** The type of the message being received. */
    public int messageType() {
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
        // Everything received counts, not only the message so far: growing
        // the buffer copies up to the limit, and the pump sets the limit to
        // the end of the message - the bytes of the next packet behind it
        // were lost with the first answer that needed a larger buffer.
        in.limit(filled);
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
        // Not open once handed over: the socket is still open, but it is
        // somebody else's now. Without this a connection whose session was
        // detached believed itself usable and reached into buffers already
        // given back - IllegalStateException instead of "closed" (08003).
        return !released && channel.isOpen();
    }

    @Override
    public void close() {
        if (released) {
            // Given up rather than ended: the socket belongs to whoever
            // continues the conversation on it, and everything of this
            // channel's own was let go in release(). Closing here would close
            // the very connection that was just handed over - which is what it
            // did, and what a session object closed after detach() then did to
            // its own successor.
            return;
        }
        // The transport swallows its own close error - see Transport#close.
        channel.close();
        out.close();
        in.close();
    }
}
