package space.seclume.oracle.net;

import java.io.IOException;
import java.nio.ByteBuffer;

import space.seclume.internal.WireBuffer;

/**
 * The line to an Oracle listener: Oracle Net Services, packet layer.
 *
 * <p>Connecting is more involved with Oracle than with the other three, because
 * a listener stands between client and database:
 *
 * <ul>
 *   <li>The client sends {@link NsPacket#TYPE_CONNECT} with a connect
 *       description as text.</li>
 *   <li>The server answers with {@link NsPacket#TYPE_ACCEPT} - then the
 *       connection stands and the packet sizes are negotiated.</li>
 *   <li>Or with {@link NsPacket#TYPE_REDIRECT}: "not me, that one over there".
 *       That is the normal case with RAC and Data Guard, but also with a single
 *       instance behind a listener. The client then connects afresh to the
 *       address it names.</li>
 *   <li>Or with {@link NsPacket#TYPE_RESEND}: "send it again".</li>
 *   <li>Or with {@link NsPacket#TYPE_REFUSE} - with the reason in the
 *       content.</li>
 * </ul>
 *
 * <p>Derived from python-oracledb v4.0.2; provenance and licence are in
 * {@code PROVENANCE.md}.
 */
public final class NsChannel implements AutoCloseable {

    /**
     * From here the connect description starts - counted <b>from the start of
     * the packet</b>, so including the eight byte header.
     */
    private static final int CONNECT_DATA_OFFSET = 74;
    /**
     * The fixed fields of the CONNECT packet.
     *
     * <p>They are written out exactly, and the unit tests hold them byte for
     * byte. That matters more here than elsewhere: an Oracle listener that
     * dislikes a field hangs up without a word - no error message, no hint. A
     * protocol you only get approximately right behaves like one you do not
     * get right at all.
     */
    private static final int VERSION_SENT = 320;
    private static final int SDU = 8192;
    private static final int TDU = 0xffff;
    /**
     * What this client wants from the NS layer.
     *
     * <p>This was {@code 0x0041} for a long time, and everything worked -
     * queries, binds, transactions, XA. It broke exactly one thing, and only
     * that one: <b>reading a LOB</b>. With bit {@code 0x0040} set the server
     * answers a LOB read with an NS packet of <b>type 15</b> that announces
     * how many bytes it has and then waits; with {@code 0x0400} it simply
     * sends the contents in a normal DATA packet, the way the reference client
     * gets them.
     *
     * <p>Everything else the driver sends matches {@code python-oracledb}
     * byte for byte - the capability arrays, the type list, the execute call,
     * the LOB call itself. The difference was in the CONNECT header, in six
     * fields; five of them change nothing. This one changes everything.
     *
     * <p>Worth keeping in mind for the next riddle of this kind: a field that
     * has been right for months can still be wrong for one feature, and Oracle
     * will not say so.
     */
    private static final int SERVICE_OPTIONS = 0x0401;
    private static final int PROTOCOL_CHARACTERISTICS = 0x7f08;
    private static final int MAX_RECEIVABLE_DATA = 0x1400;
    /**
     * The connect flags. {@code 0x41} would be wrong: with it a client
     * announces "Native Network Encryption", and the server then waits for that
     * negotiation (a packet with the marker {@code DEADBEEF}) instead of TTC -
     * and hangs up without a word when TTC arrives instead. That is exactly
     * what a real client does, and exactly why adopting the described values was
     * a mistake here.
     */
    private static final byte CONNECT_FLAGS = 0x08;
    private static final int CROSS_FACILITY = 0x0bb3;
    private static final int LARGE_SDU = 0x20000020;

    private space.seclume.internal.Transport channel;
    private final WireBuffer out = new WireBuffer(16 * 1024);
    private final WireBuffer in = new WireBuffer(32 * 1024);

    /**
     * The negotiated protocol level; it decides the header form.
     *
     * <p>Before the ACCEPT it is 0, and that matters: the CONNECT packet itself
     * still carries the <b>two-byte</b> length. Only once the server has named
     * its level may the four-byte form be used - before that nobody knows
     * whether it understands it.
     */
    private int protocolVersion;
    private int negotiatedSdu = SDU;

    /**
     * Writes every packet of this connection to {@code System.err}, framing
     * only - never contents. See {@link #trace}.
     */
    private static final boolean TRACE = Boolean.getBoolean("seclume.oracle.trace");
    private int filled;
    private int packetEnd;
    private int packetType;
    private int dataFlags;

    /**
     * TLS, when the connection runs over it - see {@link #connect}.
     *
     * <p>Unlike PostgreSQL and MySQL there is nothing to negotiate here: with
     * Oracle the encryption is a property of the endpoint. A TCPS listener
     * expects the handshake as the <b>first</b> thing on the socket and never
     * speaks NS in the clear; a TCP listener never speaks TLS. So this is
     * decided before the first packet and not afterwards.
     */
    private space.seclume.internal.TlsLayer tls;

    private NsChannel(space.seclume.internal.Transport channel) {
        this.channel = channel;
    }

    public static NsChannel connect(String host, int port, int connectTimeoutMillis)
            throws IOException {
        return connect(host, port, connectTimeoutMillis, null);
    }

    /**
     * The same, with a say in which transport carries it.
     *
     * @param transport {@code socket}, {@code ffm}, {@code ffm-if-available},
     *                  or null to take what the system property says
     */
    public static NsChannel connect(String host, int port, int connectTimeoutMillis,
            String transport) throws IOException {
        // Blocking and TCP_NODELAY live in the transport now - they belong to
        // whoever owns the descriptor, not to whoever writes packets into it.
        return new NsChannel(space.seclume.internal.Transports.open(transport, host, port, connectTimeoutMillis));
    }

    /**
     * Switches the connection to TLS - before the first NS packet.
     *
     * <p>A step of its own and not part of {@link #connect}, so that a failed
     * handshake can be told apart from an unreachable listener. They are
     * different faults and they need different answers: one is a certificate,
     * the other is a network.
     *
     * @param verify whether the certificate and the host name are checked
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
        if (tls != null) {
            // A second handshake on the same socket. This happens exactly
            // once, and only over TCPS: the listener answers the first
            // CONNECT with RESEND and hands the socket to a server process,
            // which starts a TLS session of its own. Carrying the old one on
            // gets a plaintext fatal alert, because the new peer is waiting
            // for a ClientHello and is being sent application data. See
            // OracleSession.
            tls.discard();
            tls = null;
        }
        this.tls = space.seclume.internal.TlsLayers.start(stack, channel, host, port, verify,
                identity);
    }

    /** What TLS this connection uses, or {@code null} without it. */
    public String tlsDescription() {
        return tls == null ? null : tls.description();
    }

    /**
     * Sends the CONNECT packet and reads the answer.
     *
     * @param connectString the connect description, that is the
     *                      {@code (DESCRIPTION=...)}-Text
     * @return the packet type of the answer - ACCEPT, REDIRECT, RESEND or REFUSE
     */
    public int sendConnect(String connectString) throws IOException {
        byte[] description = connectString.getBytes(java.nio.charset.StandardCharsets.US_ASCII); // seclume-allow: the connect description, protocol text and never a secret
        if (description.length > 0xffff) {
            throw new IOException("the connect description is too long: " + description.length);
        }

        out.rewind();
        out.putZeroes(NsPacket.HEADER_SIZE);           // header is filled in later
        out.putShort((short) VERSION_SENT);
        out.putShort((short) NsPacket.VERSION_MINIMUM);
        out.putShort((short) SERVICE_OPTIONS);
        out.putShort((short) SDU);
        out.putShort((short) TDU);
        out.putShort((short) PROTOCOL_CHARACTERISTICS);
        out.putShort((short) 0);                       // Line turnaround
        out.putShort((short) 0x0100);                  // a fixed value
        out.putShort((short) description.length);
        out.putShort((short) CONNECT_DATA_OFFSET);
        out.putInt(MAX_RECEIVABLE_DATA);
        out.putByte(CONNECT_FLAGS);
        out.putByte(CONNECT_FLAGS);
        out.putShort((short) 0);                       // Cross-Facility 0
        out.putShort((short) CROSS_FACILITY);
        // The rest up to the start of the description is filler, with one
        // exception: at byte 60 the packet size appears once more, this time
        // four bytes wide. That is the form which allows large SDUs.
        out.putZeroes(60 - out.position());
        out.putInt(LARGE_SDU);
        out.putZeroes(CONNECT_DATA_OFFSET - out.position());
        out.putBytes(java.lang.foreign.MemorySegment.ofArray(description), 0, description.length);

        writeHeader(out.position(), NsPacket.TYPE_CONNECT, 0);
        flush();
        return nextPacket();
    }

    /**
     * Starts a DATA packet - TTC sits inside it, the actual database
     * protocol.
     *
     * <p>Unlike with CONNECT, the negotiated header form applies here: after
     * an ACCEPT with version 320 the length is four bytes wide.
     */
    public WireBuffer beginData() {
        out.rewind();
        out.putZeroes(NsPacket.HEADER_SIZE);
        out.putShort((short) 0);                       // data flags
        if (piggyback != null) {
            piggyback.writeInto(out);
        }
        return out;
    }

    /**
     * Something to write at the head of every DATA packet.
     *
     * <p>There is exactly one use of it - {@link TtcClose}, giving cursors
     * back - and it is a hook rather than a call at each send site for the
     * reason every such thing is: a driver has several places that send, and
     * one of them written later would forget. See
     * {@code OracleSession.nextCall}, which is the same argument about call
     * numbers.
     */
    @FunctionalInterface
    public interface Piggyback {
        /** Writes nothing when there is nothing to say. */
        void writeInto(WireBuffer out);
    }

    private Piggyback piggyback;

    /** Sets what rides in front of the next calls, or {@code null} for none. */
    public void piggyback(Piggyback writer) {
        this.piggyback = writer;
    }

    /**
     * Sends a marker packet.
     *
     * <p>Markers are the protocol's out-of-band channel: the server uses them
     * to say "stop what you are doing, an answer of a different kind is
     * coming", and it waits for the client to acknowledge with a reset before
     * it sends that answer. A client that does not answer waits forever - and
     * that looks like a hung network, not like a protocol step.
     *
     * <p>The body is three bytes and always the same shape: {@code 01 00} and
     * the marker type.
     */
    public void sendMarker(int markerType) throws IOException {
        out.rewind();
        out.putZeroes(NsPacket.HEADER_SIZE);
        out.putByte((byte) 1);
        out.putByte((byte) 0);
        out.putByte((byte) markerType);
        writeHeader(out.position(), NsPacket.TYPE_MARKER, 0);
        flush();
    }

    /**
     * Answers the server's markers and reads on until a packet that is not
     * one.
     *
     * <p><b>Oracle does not simply send an error.</b> It sends a break marker
     * and a reset marker and waits for the client to answer with a reset of
     * its own; only then does the error arrive. A caller that does not know
     * this sees a MARKER where it expected data and reports whatever it
     * happens to be doing as broken - which is how a rejected password came
     * to be reported as a failed connection, with the SQLState of one.
     *
     * <p>Here rather than in each caller because it is a property of this
     * layer, and because two implementations of it drift: the login had none
     * and the statement path had one for months.
     *
     * @param type the packet type just read
     * @return the type of the first packet that was not a marker
     */
    public int answerMarkers(int type) throws IOException {
        boolean sawReset = false;
        int current = type;
        while (current == NsPacket.TYPE_MARKER) {
            synchronized (breakLock) {
                // The server is answering a break - or a failure, which
                // clears the way the same. Either way nothing is owed.
                breakInFlight = false;
                lateBreak = false;
            }
            sawReset |= markerType() == NsPacket.MARKER_RESET;
            if (sawReset) {
                sendMarker(NsPacket.MARKER_RESET);
                sawReset = false;
            }
            current = nextPacket();
        }
        return current;
    }

    /**
     * Reads the server's late answer to a break and throws it away - the
     * markers, the reset they ask for, and the error behind them.
     *
     * <p>Only reached when a call ended without its caller asking
     * {@link #takeLateBreak()}: the LOB calls, the login. The call has
     * already reported its outcome, and the error belongs to nothing that is
     * still running; left on the wire, it would be the next statement's.
     */
    private void discardLateBreak() throws IOException {
        lateBreak = false;
        int type = answerMarkers(nextPacket());
        while (type == NsPacket.TYPE_DATA
                && (dataFlags & NsPacket.DATA_FLAGS_END_OF_RESPONSE) == 0) {
            type = answerMarkers(nextPacket());
        }
    }

    /** The kind of a marker packet, out of its body. */
    public int markerType() {
        return in.getByte(NsPacket.HEADER_SIZE + 2) & 0xff;
    }

    /**
     * How often this connection has waited for an answer.
     *
     * <p>Counted here because this is the one place every request goes
     * through. See {@link space.seclume.RoundTrips} for what the
     * number is good for.
     */
    private long roundTrips;

    /** Every byte of every packet received - what a fetch size is sized by. */
    private long bytesReceived;

    public long bytesReceived() {
        return bytesReceived;
    }

    public long roundTrips() {
        return roundTrips;
    }

    /**
     * Whether a request has gone out whose answer has not arrived in full.
     *
     * <p>Only read by {@link #sendBreak()}, and it is what makes that method
     * safe. Oracle answers a break with markers of its own, and those markers
     * are read by whoever is waiting for the answer. Sent when nobody is
     * waiting, they would sit on the wire until the next statement read them
     * instead of its own answer.
     *
     * <p>Volatile: set and cleared on the working thread, read on the thread
     * that cancels.
     */
    private volatile boolean awaitingAnswer;

    /**
     * Guards the moment a break is sent against the moment an answer ends.
     *
     * <p>Without it, a break could be judged "in flight" just before the
     * answer's last packet was read, and nobody would expect the markers it
     * provokes.
     */
    private final Object breakLock = new Object();

    /** A break went out during the call now in flight, and no marker has answered it yet. */
    private boolean breakInFlight;

    /**
     * The call ended normally although a break was sent during it - so the
     * server will act on the break <b>after</b> the answer: markers, and an
     * ORA-01013 behind them.
     *
     * <p>Measured against 23ai: a PL/SQL block in {@code dbms_session.sleep}
     * finishes its sleep, answers as if nothing had happened, and only then
     * takes the break. The markers and the error were then read by the
     * <b>next</b> statement, which failed as "cancelled" - a query timeout
     * that fired late cancelled the wrong statement. python-oracledb reports
     * the ORA-01013 on the call that was cancelled, and so does this driver
     * now: see {@link #takeLateBreak()}. {@link #sendData()} clears a late
     * break nobody took before the next request goes out.
     */
    private volatile boolean lateBreak;

    /**
     * Whether the answer just read is followed by the server's reaction to a
     * break - and if so, it is now the caller's to read. Asking clears it.
     */
    public boolean takeLateBreak() {
        synchronized (breakLock) {
            boolean owed = lateBreak;
            lateBreak = false;
            return owed;
        }
    }

    /**
     * Tells the server to abandon the call this connection is waiting on.
     *
     * <p>Oracle's break is a MARKER packet down the same socket - the
     * connection running the call is blocked reading, and a socket is full
     * duplex, so the write does not wait for the read. What comes back is not
     * an error but <b>more markers</b>: a break and a reset, which the reading
     * thread answers with a reset of its own (see {@link #answerMarkers}), and
     * only then does {@code ORA-01013} arrive as an ordinary TTC error. That
     * whole dance already existed here for failed statements; a break is the
     * same conversation started from this end.
     *
     * <p><b>Its own buffer, not the send buffer.</b> This is called from
     * another thread by definition, and the send buffer belongs to whoever
     * wrote the request that is currently in flight.
     *
     * <p>Does nothing when no call is in flight, and that is not laziness: the
     * markers the server would answer with have no reader, and the next
     * statement would find them where its own answer should be. A
     * query-timeout thread that fires just after its query finished is the
     * ordinary case, not the exotic one.
     *
     * <p><b>The urgent byte first, and the marker is not enough without it.</b>
     * Measured against a real 23ai listener: the marker packet alone goes out,
     * framed exactly as the reset marker that already works in the failure
     * path, and the server carries on sleeping. It is not reading the socket -
     * it is running the statement - so the marker waits in its receive buffer
     * until the thing it was meant to stop has finished. The {@code !} sent as
     * TCP urgent data is what raises {@code SIGURG} on the far side and makes
     * the server look up. Oracle accepts the marker on its own only when the
     * listener is configured with {@code DISABLE_OOB=ON}, which is why the
     * marker is still sent behind it rather than instead of it.
     *
     * <p><b>When the server acts on it</b> is the server's affair: a
     * long-running query is interrupted within the second, a PL/SQL block in
     * {@code dbms_session.sleep} sleeps to its end first - python-oracledb
     * sees the same against the same server. Then the answer arrives as if
     * nothing had happened and the break's markers follow it; see
     * {@link #lateBreak} for whose they are.
     *
     * <p>The urgent byte goes to the <b>transport</b> and not through the TLS
     * layer, which is correct and not a shortcut: it is a signal on the
     * connection rather than data in the stream, and TLS has nowhere to put
     * it. A transport that cannot send urgent data says so and the marker
     * goes on its own - which is the right behaviour for a listener that
     * disabled OOB, and no worse than nothing for one that did not.
     *
     * @return whether a break was actually sent
     */
    public boolean sendBreak() throws IOException {
        synchronized (breakLock) {
            if (TRACE) {
                System.err.println("[ns] -> break, " + (awaitingAnswer
                        ? "a call is in flight" : "nothing in flight - not sent"));
            }
            if (!awaitingAnswer) {
                return false;
            }
            breakInFlight = true;
            return writeBreak();
        }
    }

    private boolean writeBreak() throws IOException {
        try {
            // The byte itself carries no meaning to Oracle beyond "there is
            // urgent data"; '!' is what every client sends.
            channel.sendUrgent('!');
        } catch (IOException cannot) {
            // A transport without urgent data. The marker below still reaches
            // a listener with DISABLE_OOB=ON.
        }
        WireBuffer marker = new WireBuffer(NsPacket.HEADER_SIZE + 3);
        marker.putZeroes(NsPacket.HEADER_SIZE);
        marker.putByte((byte) 1);
        marker.putByte((byte) 0);
        marker.putByte((byte) NsPacket.MARKER_TYPE_BREAK);
        int length = marker.position();
        if (NsPacket.hasLargeLength(protocolVersion)) {
            marker.putByteAt(0, (byte) (length >>> 24));
            marker.putByteAt(1, (byte) (length >>> 16));
            marker.putByteAt(2, (byte) (length >>> 8));
            marker.putByteAt(3, (byte) length);
        } else {
            marker.putByteAt(0, (byte) (length >>> 8));
            marker.putByteAt(1, (byte) length);
        }
        marker.putByteAt(4, (byte) NsPacket.TYPE_MARKER);
        java.nio.ByteBuffer view = marker.view();
        view.clear().position(0).limit(length);
        writeAll(view);
        return true;
    }

    /**
     * The flight recorder, or {@code null} when nobody asked for one.
     *
     * <p>See {@link space.seclume.Flight}.
     */
    private space.seclume.internal.FlightRecorder flight;
    /**
     * Whether the message being written carries the credential.
     *
     * <p><b>Oracle's answer to the withholding question is different again.</b>
     * The password never travels as itself: O5LOGON sends it AES-encrypted and
     * hex-encoded, so the length of the second login message is the length of
     * a ciphertext rounded up to the block size - which is the password's
     * length to within sixteen bytes. Coarser than PostgreSQL's cleartext case
     * and finer than nothing, and a ring buffer in this process is the wrong
     * place to keep either.
     */
    private boolean writingCredential;

    /** Switches the recording on - see {@link space.seclume.Flight}. */
    public void recordFlight(space.seclume.internal.FlightRecorder recorder) {
        this.flight = recorder;
    }

    /** What this connection last sent and received, oldest first. */
    public java.util.List<space.seclume.Flight.Message> recentMessages() {
        return flight == null ? java.util.List.of() : flight.recent();
    }

    /** How many packets have crossed this connection. */
    public long recordedMessages() {
        return flight == null ? 0 : flight.messages();
    }

    /** The tail of the recording, or {@code null} when there is none. */
    public String flightTail() {
        return flight == null ? null : flight.tail(8);
    }

    /** The next DATA packet carries the credential - see {@link #writingCredential}. */
    public void nextPacketCarriesTheCredential() {
        this.writingCredential = true;
    }

    /**
     * The name of what is in a packet, for a diagnostic.
     *
     * <p>A DATA packet is named by its TTC message type, because every one of
     * them is a DATA packet and a recording that said so ten times in a row
     * would show nothing. The other packet types name themselves.
     */
    private String nameOf(int packetType, int ttc) {
        if (packetType != NsPacket.TYPE_DATA) {
            return NsPacket.typeName(packetType);
        }
        return ttc < 0 ? "DATA" : "DATA/" + TtcMessage.typeName(ttc);
    }

    /** Finishes the DATA packet and sends it. */
    public void sendData() throws IOException {
        if (lateBreak) {
            discardLateBreak();
        }
        synchronized (breakLock) {
            awaitingAnswer = true;
            breakInFlight = false;
        }
        roundTrips++;
        if (flight != null) {
            int ttc = out.position() > NsPacket.HEADER_SIZE + NsPacket.DATA_FLAGS_SIZE
                    ? out.getByte(NsPacket.HEADER_SIZE + NsPacket.DATA_FLAGS_SIZE) & 0xff
                    : -1;
            flight.record(true, nameOf(NsPacket.TYPE_DATA, ttc),
                    writingCredential ? space.seclume.Flight.WITHHELD : out.position());
            writingCredential = false;
        }
        int total = out.position();
        if (total <= negotiatedSdu) {
            writeHeader(total, NsPacket.TYPE_DATA, 0);
            flush();
            return;
        }
        sendSplit(total);
    }

    /**
     * Sends a message that is larger than one packet.
     *
     * <p>A 200 000 character bind value does not fit in a packet, and the
     * server does not say so politely: it resets the connection. The reference
     * client splits, and measurement says exactly how - packets of the
     * negotiated SDU, data flags zero on every one of them, and only the
     * <b>first</b> carries the TTC message type. Everything after it is raw
     * continuation, the same shape in which large answers arrive.
     *
     * <p>No copying: the ten bytes a continuation packet needs for its own
     * header sit directly in front of its payload, and they belong to the
     * packet before it - which has already gone out.
     */
    private void sendSplit(int total) throws IOException {
        final int prefix = NsPacket.HEADER_SIZE + 2;   // header plus the data flags
        final int payload = negotiatedSdu - prefix;
        int at = prefix;
        while (at < total) {
            int length = Math.min(payload, total - at);
            int start = at - prefix;
            writeHeaderAt(start, prefix + length, NsPacket.TYPE_DATA, 0);
            out.putByteAt(start + NsPacket.HEADER_SIZE, (byte) 0);
            out.putByteAt(start + NsPacket.HEADER_SIZE + 1, (byte) 0);
            writeRange(start, prefix + length);
            at += length;
        }
        out.clear();
    }

    /** Fills length, type and flags into the packet header. */
    private void writeHeader(int length, int type, int flags) {
        writeHeaderAt(0, length, type, flags);
    }

    /** The same, for a packet that does not start at the beginning of the buffer. */
    private void writeHeaderAt(int offset, int length, int type, int flags) {
        if (NsPacket.hasLargeLength(protocolVersion)) {
            putBigEndian(offset, length, 4);
        } else {
            putBigEndian(offset, length, 2);
            putBigEndian(offset + 2, 0, 2);
        }
        out.putByteAt(offset + 4, (byte) type);
        out.putByteAt(offset + 5, (byte) flags);
        out.putByteAt(offset + 6, (byte) 0);
        out.putByteAt(offset + 7, (byte) 0);
    }

    private void putBigEndian(int at, int value, int length) {
        for (int i = 0; i < length; i++) {
            out.putByteAt(at + i, (byte) (value >>> (8 * (length - 1 - i))));
        }
    }

    private void flush() throws IOException {
        writeRange(0, out.position());
        out.clear();
    }

    /** Writes a buffer that is not the send buffer - see {@link #sendBreak}. */
    private void writeAll(ByteBuffer view) throws IOException {
        if (tls != null) {
            tls.write(view);
            return;
        }
        while (view.hasRemaining()) {
            channel.write(view);
        }
    }

    /** Writes one stretch of the send buffer, whole. */
    private void writeRange(int from, int length) throws IOException {
        if (TRACE) {
            trace("->", in(out, from + 4), in(out, from + 5), length,
                    from + 10 < out.position() ? in(out, from + 8) * 256 + in(out, from + 9) : 0,
                    from + 12 <= out.position() ? in(out, from + 10) : -1,
                    from + 13 <= out.position() ? in(out, from + 11) : -1,
                    from + 14 <= out.position() ? in(out, from + 12) : -1);
        }
        ByteBuffer view = out.view();
        view.clear().position(from).limit(from + length);
        if (tls != null) {
            tls.write(view);
        } else {
            while (view.hasRemaining()) {
                channel.write(view);
            }
        }
    }

    /**
     * Reads the next packet.
     *
     * @return the packet type; the buffer then stands at the content
     */
    public int nextPacket() throws IOException {
        // Whatever the socket already delivered beyond the last packet stays.
        // Two markers arrive in one go, and a client that throws the second one
        // away waits for a packet it has already read - which looks like a hung
        // network and is none. The same mistake cost a day in the TDS channel.
        int leftover = filled - packetEnd;
        if (leftover > 0) {
            java.lang.foreign.MemorySegment.copy(in.segment(), packetEnd,
                    in.segment(), 0, leftover);
        }
        // What is behind the leftover is the packet just consumed - rows, a
        // LOB, whatever the server sent. It stays in native memory until
        // something longer happens to cover it, which after a long answer
        // followed by a short one is never. The heap dump harness cannot see
        // this buffer, so nothing else would have found it.
        int keep = Math.max(leftover, 0);
        in.segment().asSlice(keep, in.capacity() - keep).fill((byte) 0);
        in.rewind();
        filled = keep;
        packetEnd = 0;
        fill(NsPacket.HEADER_SIZE);
        int length;
        if (NsPacket.hasLargeLength(protocolVersion)) {
            length = readBigEndian(0, 4);
        } else {
            length = readBigEndian(0, 2);
        }
        if (length < NsPacket.HEADER_SIZE) {
            throw new IOException("the server announced a packet of " + length + " bytes");
        }
        // And an upper bound, because the lower one alone lets a length off
        // the wire reach an allocator. A four-byte length of 0x7fffffff grew
        // the receive buffer towards two gigabytes and failed inside the JDK
        // with "Segment is too large to wrap as ByteBuffer" - an
        // IllegalStateException out of executeQuery, on the way to an
        // OutOfMemoryError on a machine with more room. The negotiated SDU is
        // what the two ends agreed this connection would use; anything beyond
        // it is not a packet this conversation can contain.
        int most = Math.max(negotiatedSdu, SDU) * 2;
        if (length > most) {
            throw new IOException("the server announced a packet of " + length
                    + " bytes, and this connection negotiated " + negotiatedSdu);
        }
        packetType = in.getByte(4) & 0xff;
        fill(length);
        packetEnd = length;
        bytesReceived += length;
        in.position(NsPacket.HEADER_SIZE);
        in.limit(length);

        if (packetType == NsPacket.TYPE_DATA) {
            dataFlags = readBigEndian(NsPacket.HEADER_SIZE, 2);
            in.position(NsPacket.HEADER_SIZE + NsPacket.DATA_FLAGS_SIZE);
            if ((dataFlags & NsPacket.DATA_FLAGS_END_OF_RESPONSE) != 0) {
                // The answer is complete: from here until the next request
                // nobody is waiting, and a break would have no reader for the
                // markers it provokes. See sendBreak - and lateBreak for a
                // break the server has not acted on yet.
                synchronized (breakLock) {
                    awaitingAnswer = false;
                    if (breakInFlight) {
                        breakInFlight = false;
                        lateBreak = true;
                    }
                }
            }
        } else {
            dataFlags = 0;
        }
        if (flight != null) {
            int at = in.position();
            flight.record(false, nameOf(packetType,
                    packetType == NsPacket.TYPE_DATA && at < in.limit()
                            ? in.getByte(at) & 0xff : -1), length);
        }
        if (TRACE) {
            int at = in.position();
            trace("<-", packetType, in.getByte(5) & 0xff, length, dataFlags,
                    at < in.limit() ? in.getByte(at) & 0xff : -1,
                    at + 1 < in.limit() ? in.getByte(at + 1) & 0xff : -1,
                    at + 2 < in.limit() ? in.getByte(at + 2) & 0xff : -1);
        }
        return packetType;
    }

    /**
     * Writes down every packet, in both directions.
     *
     * <p>For the one question that decides such cases: <b>who is waiting for
     * whom</b>. A driver that reads an answer nobody owes it hangs, and the
     * stack trace then points at a socket read and says nothing about the
     * request that never was. The record shows it at a glance - every line is
     * one packet, and the last outgoing one before a read that never returns is
     * the culprit.
     *
     * <p><b>Contents are never written down</b>, only the frame: direction,
     * packet type, flags, length, and the first three bytes of the TTC message,
     * which are message type, function and sequence number. The login travels
     * through here too, and a trace switch that leaks a password would be a
     * worse bug than the one it is meant to find.
     */
    private void trace(String direction, int type, int flags, int length, int dataFlags,
                       int ttcType, int ttcFunction, int ttcSequence) {
        StringBuilder line = new StringBuilder(96); // seclume-allow: protocol frame, never content
        line.append("[ns] ").append(direction)
                .append(" typ=").append(type)
                .append(" flags=0x").append(Integer.toHexString(flags))
                .append(" len=").append(length)
                .append(" datenflags=0x").append(Integer.toHexString(dataFlags));
        // Only a DATA packet carries a TTC message; for the others the bytes
        // at that place mean something else, and printing them as a message
        // type would send the reader after a ghost.
        if (type == NsPacket.TYPE_DATA && ttcType >= 0) {
            line.append(" ttc=").append(ttcType).append(' ')
                    .append(TtcMessage.typeName(ttcType));
            if (ttcType == TtcMessage.TYPE_FUNCTION) {
                line.append(" funktion=").append(ttcFunction)
                        .append(" folge=").append(ttcSequence);
            }
        }
        System.err.println(line);
    }

    private static int in(space.seclume.internal.WireBuffer buffer, int at) {
        return buffer.getByte(at) & 0xff;
    }

    private int readBigEndian(int at, int length) {
        int value = 0;
        for (int i = 0; i < length; i++) {
            value = (value << 8) | (in.getByte(at + i) & 0xff);
        }
        return value;
    }

    /**
     * Evaluates an ACCEPT: the server names the protocol level it speaks and
     * the packet size it settles for.
     */
    public void readAccept() {
        int version = readBigEndian(NsPacket.HEADER_SIZE, 2);
        int sdu = readBigEndian(NsPacket.HEADER_SIZE + 4, 2);
        this.protocolVersion = version;
        this.negotiatedSdu = sdu > 0 ? sdu : SDU;
    }

    /**
     * The address from a REDIRECT - the server sends a new connect
     * description the client is meant to connect to afresh.
     */
    public String readRedirect() {
        int length = readBigEndian(NsPacket.HEADER_SIZE, 2);
        in.position(NsPacket.HEADER_SIZE + 2);
        in.limit(NsPacket.HEADER_SIZE + 2 + length);
        return in.readString(length);
    }

    /** The reason from a REFUSE - text the server sends along. */
    public String readRefuse() {
        int rest = packetEnd - (NsPacket.HEADER_SIZE + 2);
        if (rest <= 0) {
            return "";
        }
        in.position(NsPacket.HEADER_SIZE + 2);
        in.limit(packetEnd);
        return in.readString(rest);
    }

    private void fill(int needed) throws IOException {
        while (filled < needed) {
            in.ensureCapacity(Math.max(needed, in.capacity()));
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

    /** A channel on a transport somebody else opened - see OracleSession#resume. */
    public static NsChannel over(space.seclume.internal.Transport transport, int protocolVersion) {
        NsChannel channel = new NsChannel(transport);
        channel.protocolVersion = protocolVersion;
        return channel;
    }

    /**
     * A channel over a stream that already has a TLS layer on it.
     *
     * <p>The counterpart to {@link #tlsLayer()}: the stream was handed on
     * while encrypted, and the encryption goes with it. The server is told
     * nothing and notices nothing - the same TLS connection simply carries
     * on, which is why the session on it survives.
     */
    public static NsChannel over(space.seclume.internal.Transport transport, int protocolVersion,
            space.seclume.internal.TlsLayer tls) {
        NsChannel channel = over(transport, protocolVersion);
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

    /** Whether this connection is carried by TLS at all. */
    public boolean isEncrypted() {
        return tls != null;
    }

    /** The transport carrying this channel - for whoever has to hand it on. */
    public space.seclume.internal.Transport transport() {
        return channel;
    }

    /**
     * Whether nothing is half-written and no packet is half-read.
     *
     * <p>{@code filled} beyond {@code packetEnd} is not work in flight: the
     * socket delivers markers in pairs, and the second one waiting in the
     * buffer belongs to this conversation. What would be in flight is a packet
     * whose body has not arrived, and that cannot be the case between calls.
     */
    public boolean isIdle() {
        return out.position() == 0;
    }

    /** Puts another transport under this channel; the old one is not closed. */
    public void replaceTransport(space.seclume.internal.Transport replacement)
            throws java.io.IOException {
        if (!isIdle()) {
            throw new java.io.IOException("this channel has " + out.position()
                    + " bytes unsent");
        }
        this.channel = replacement;
        if (tls != null) {
            tls.replaceTransport(replacement);
        }
    }

    /** Gives the channel up without closing the transport - see OracleSession#detach. */
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

    public int protocolVersion() {
        return protocolVersion;
    }

    public int negotiatedSdu() {
        return negotiatedSdu;
    }

    public int dataFlags() {
        return dataFlags;
    }

    public WireBuffer packet() {
        return in;
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
        if (tls != null) {
            // Says goodbye and releases the keys. On the own stack those are
            // native memory this layer allocated, so skipping it would leak
            // an arena per connection.
            tls.close();
        }
        // The transport swallows its own close error - see Transport#close.
        channel.close();
        out.close();
        in.close();
    }
}
