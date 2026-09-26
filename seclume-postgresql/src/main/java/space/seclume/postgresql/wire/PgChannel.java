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
    private space.seclume.internal.TlsLayer tls;
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
     * Asks the server to stop what another connection is doing.
     *
     * <p>Sixteen bytes and no type tag, the same shape as the TLS request: a
     * length of 16, the marker 80877102, and the process id and secret key the
     * server handed out in {@code BackendKeyData} when <b>that other</b>
     * connection logged in. There is no answer and there is no acknowledgement
     * - the server either finds a backend with that key and signals it, or
     * does nothing, and either way it closes this connection.
     *
     * <p>That is why cancellation needs a second connection at all. The one
     * running the query is busy waiting for its answer; a message written into
     * it would sit in the send buffer until the query it was meant to stop had
     * finished.
     *
     * <p>The key is a capability, not a credential: anyone holding it can stop
     * that backend's current query and nothing else. It travels over TLS when
     * the connection it belongs to used TLS, for the same reason - it should
     * not be readable off the wire.
     */
    public void sendCancelRequest(int processId, int secretKey) throws IOException {
        out.clear();
        out.putInt(16);
        out.putInt(80877102);
        out.putInt(processId);
        out.putInt(secretKey);
        flush();
        out.clear();
    }

    /**
     * Whether a request has gone out whose answer has not arrived in full.
     *
     * <p>What {@code cancel()} asks before sending anything. PostgreSQL's
     * CancelRequest names a backend and not a statement: sent in the gap
     * between two statements it stops the <b>next</b> one, and the caller
     * sees a statement it never cancelled fail with 57014. libpq has that
     * race and does not close it; this closes the wide half of it, which is
     * the half a query-timeout thread hits every time its query finishes
     * first.
     *
     * <p>The narrow half stays: a cancellation decided here can still be
     * overtaken by the answer arriving. Nothing on the client can prevent
     * that, and nothing here pretends to.
     *
     * <p>Volatile: set and cleared on the working thread, read on the thread
     * that cancels.
     */
    public boolean isAwaitingAnswer() {
        return awaitingAnswer;
    }

    private volatile boolean awaitingAnswer;

    /** ReadyForQuery messages asked for and not yet flushed. */
    private int unsentReady;

    /** ReadyForQuery messages flushed and not yet read. */
    private int outstandingReady;

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
        startTls(host, port, verify, space.seclume.internal.jdbc.TlsStack.JSSE);
    }

    /**
     * The same, with a say in which TLS implementation carries it.
     *
     * @param stack {@code JSSE} for the JDK's engine, {@code SECLUME} for this
     *              project's own TLS 1.3 client - see
     *              {@link space.seclume.internal.jdbc.TlsStack}
     */
    public void startTls(String host, int port, boolean verify,
            space.seclume.internal.jdbc.TlsStack stack) throws IOException {
        startTls(host, port, verify, stack, null);
    }

    /**
     * The same, proving who the client is as well.
     *
     * @param identity a client certificate to present if the server asks for
     *                 one, or {@code null}. It is <b>not</b> closed here: it
     *                 is shared by every connection configured the same way
     */
    public void startTls(String host, int port, boolean verify,
            space.seclume.internal.jdbc.TlsStack stack,
            space.seclume.tls.ClientIdentity identity) throws IOException {
        this.tls = space.seclume.internal.TlsLayers.start(stack, channel, host, port, verify,
                identity);
    }

    /** The same, offering one application protocol and requiring it back - direct TLS. */
    public void startTls(String host, int port, boolean verify,
            space.seclume.internal.jdbc.TlsStack stack,
            space.seclume.tls.ClientIdentity identity, String alpn) throws IOException {
        this.tls = space.seclume.internal.TlsLayers.start(stack, channel, host, port, verify,
                identity, alpn);
    }

    /** The server's certificate, or {@code null} without TLS - for channel binding. */
    public java.security.cert.X509Certificate peerCertificate() throws IOException {
        return tls == null ? null : tls.peerCertificate();
    }

    /** What TLS is in use, for the preflight report; {@code null} without it. */
    public String tlsDescription() {
        return tls == null ? null : tls.description();
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

    /**
     * A channel over a stream that already has a TLS layer on it.
     *
     * <p>The counterpart to {@link #tlsLayer()}: the stream was handed on
     * while encrypted, and the encryption goes with it. The server is told
     * nothing and notices nothing - the same TLS connection simply carries
     * on, which is why the session on it survives.
     */
    public static PgChannel over(space.seclume.internal.Transport transport,
            space.seclume.internal.TlsLayer tls) {
        PgChannel channel = new PgChannel(transport);
        channel.tls = tls;
        return channel;
    }

    /** For tests: an already connected channel. */
    public static PgChannel wrap(java.nio.channels.SocketChannel channel) {
        return new PgChannel(space.seclume.internal.SocketTransport.wrap(channel));
    }

    // ---- writing ---------------------------------------------------------

    /**
     * The flight recorder, or {@code null} when nobody asked for one.
     *
     * <p>Null rather than a recorder that does nothing: this is checked once
     * per message on every connection, and the common case is that it is not
     * there. See {@link space.seclume.Flight}.
     */
    private space.seclume.internal.FlightRecorder flight;
    /** The tag of the message being written, for the recorder. */
    private byte writing;

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

    /** Starts a message with a type tag. */
    public WireBuffer begin(byte tag) {
        if (tag == 'Q' || tag == 'S') {
            unsentReady++;          // each Query and each Sync ends in one ReadyForQuery
        }
        writing = tag;
        out.putByte(tag);
        lengthAt = out.position();
        out.putInt(0);              // a placeholder
        return out;
    }

    /** Starts the startup message, which has no type tag. */
    public WireBuffer beginUntagged() {
        writing = 0;
        lengthAt = out.position();
        out.putInt(0);
        return out;
    }

    /** Fills in the length afterwards and finishes the message. */
    public void end() {
        if (lengthAt < 0) {
            throw new IllegalStateException("no message was started");
        }
        int length = out.position() - lengthAt;
        out.putInt(lengthAt, length);
        lengthAt = -1;
        if (flight != null) {
            // Recorded when the message is finished rather than when it is
            // flushed: several messages go out in one flush, and a recording
            // that showed them as one would hide exactly the case it exists
            // for.
            // The count is withheld for the message that carries the
            // credential - under cleartext authentication its length is the
            // password's length. See space.seclume.Flight.WITHHELD.
            flight.record(true, space.seclume.postgresql.PgProtocol.nameOf(writing),
                    writing == space.seclume.postgresql.PgProtocol.PASSWORD
                            ? space.seclume.Flight.WITHHELD : length + 1);
        }
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
        outstandingReady += unsentReady;
        unsentReady = 0;
        awaitingAnswer = true;
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
        if (tag == 'Z') {
            // ReadyForQuery: the server has finished and is waiting for the
            // next request. From here until something is flushed, nobody is
            // running and a cancellation has nothing to cancel - see
            // isAwaitingAnswer. Unless more were asked for in the same
            // flush: a deferred BEGIN rides in front of a statement, answers
            // at once, and the statement behind it is still running. Taking
            // the first ReadyForQuery for the last made every query timeout
            // inside a transaction a no-op - the cancel was judged to have
            // nothing to cancel. Found by the Spring JDBC suite.
            if (outstandingReady > 0) {
                outstandingReady--;
            }
            awaitingAnswer = outstandingReady > 0;
        }
        int length = in.getInt();
        if (length < 4 || length > MAX_MESSAGE) {
            throw new IOException("the server announced a message of " + length + " bytes");
        }
        int payload = length - 4;
        fill(payload);
        if (flight != null) {
            flight.record(false, space.seclume.postgresql.PgProtocol.nameOf(tag), length + 1);
        }
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

    /**
     * PostgreSQL's own ceiling for one message, and therefore this driver's.
     *
     * <p>Not a guess: the server refuses to build a message larger than a
     * gigabyte, so anything above it did not come from PostgreSQL.
     */
    private static final int MAX_MESSAGE = 0x3fff_ffff;

    /**
     * Reads until the buffer holds {@code needed} bytes beyond the cursor.
     *
     * <p><b>The buffer grows towards the announcement, never to it.</b> The
     * first version passed the announced size straight to
     * {@code ensureCapacity}, which is fine when the bytes are coming and
     * catastrophic when they are not: a message announcing a gigabyte and
     * sending sixty bytes made every single read allocate a gigabyte, copy
     * into it, and wipe the old one - the wipe being the thing this project
     * does on purpose, and the thing that turns a large allocation into a
     * large amount of work. Sixty bytes cost sixty gigabyte-wipes, and the
     * fuzz sweep saw it as a session that never returned.
     *
     * <p>Growing geometrically instead means the cost follows the bytes that
     * actually arrive. The stream then ends where it always would, and the
     * message is refused for the right reason.
     */
    private void fill(int needed) throws IOException {
        while (filled - in.position() < needed) {
            long wanted = Math.min((long) filled + needed,
                    Math.max((long) in.capacity() * 2, filled + 1L));
            in.ensureCapacity((int) Math.min(wanted, MAX_MESSAGE + 8L));
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


    // ---- replacing what is underneath -------------------------------------

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
        if (released) {
            // Given up rather than ended: the socket belongs to whoever
            // continues the conversation on it, and everything of this
            // channel's own was let go in release(). Closing here would close
            // the very connection that was just handed over.
            return;
        }
        if (tls != null) {
            // Says goodbye and releases the keys. On the own stack those are
            // native memory this layer allocated, so skipping it would leak
            // an arena per connection - the JSSE layer forgave that, which is
            // why it went unnoticed for as long as there was only one stack.
            tls.close();
        }
        // The transport swallows its own close error - see Transport#close.
        channel.close();
        out.close();
        in.close();
    }

    public boolean isOpen() {
        return !released && channel.isOpen();
    }

    /**
     * Whether this channel has been given up in favour of somebody else.
     *
     * <p>See {@link #release()}: the transport lives on, this object does not.
     */
    private boolean released;

    /**
     * Gives the channel up <b>without</b> closing the transport.
     *
     * <p>For the one case where the stream outlives the session object: the
     * connection was authenticated here and is handed on to whoever continues
     * it. Closing here would close the very socket that is about to carry the
     * conversation, and not closing at all would leak the two buffers, which
     * are native memory this channel allocated.
     *
     * <p>Afterwards this channel reports itself closed, so a caller that kept
     * a reference gets an error instead of writing into a stream somebody else
     * now owns.
     */
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
            // Let go of the keys, keep the socket - the same distinction
            // TlsLayer.discard exists for.
            tls.discard();
        }
        out.close();
        in.close();
    }
}
