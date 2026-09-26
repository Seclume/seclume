package space.seclume.tls;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;

import space.seclume.internal.Transport;

/**
 * A finished TLS connection: bytes in, bytes out, encryption in between.
 *
 * <p>It is a {@link Transport} on purpose. That is the interface every
 * driver in this project already reads and writes through, so an encrypted
 * connection is not a special case anywhere above it - the same PostgreSQL
 * or Oracle code runs over a socket or over this without knowing which.
 *
 * <p><b>What it deals with that a plain socket does not.</b> A TLS 1.3 peer
 * may send handshake messages long after the handshake: OpenSSL servers
 * routinely send session tickets a moment after Finished, and either side
 * may ask to change keys. Those arrive interleaved with real data on the
 * same connection, and a reader that returned them as application bytes
 * would hand a driver protocol garbage at a random moment - the kind of
 * fault that shows up once a week under load and never in a test. They are
 * handled here instead:
 *
 * <ul>
 *   <li><b>NewSessionTicket</b> is dropped. Nothing here resumes sessions
 *       yet, and holding a ticket we will not use only keeps material alive;
 *   <li><b>KeyUpdate</b> rotates the reading keys, and when the peer asks
 *       for one in return, ours are rotated and a KeyUpdate sent back. The
 *       sequence number restarting at zero is part of that, and getting it
 *       wrong would look like a working connection until the first record
 *       after the switch;
 *   <li><b>anything else is refused</b>, and so is a KeyUpdate that is not
 *       exactly one byte of 0 or 1, or that does not end its record: the
 *       peer is told why ({@code unexpected_message} or
 *       {@code illegal_parameter}) and the connection is closed. Dropping
 *       an unknown message quietly would mean reading on in a state nobody
 *       agreed to.
 * </ul>
 *
 * <p>Both traffic secrets stay off-heap for the life of the connection, in
 * the {@link RecordProtection}s this owns - which is the whole reason this
 * class exists rather than an {@code SSLEngine}.
 */
public final class TlsConnection implements Transport {

    private static final int NEW_SESSION_TICKET = Handshake.NEW_SESSION_TICKET;
    private static final int KEY_UPDATE = 24;

    /** Not final: see {@link #replaceTransport}. */
    private Transport underlying;
    private final RecordStream records;
    private final Arena arena = Arena.ofShared();
    private final MemorySegment scratch;
    private final HandshakeReassembler postHandshake;

    /** What is left of the last record read, not yet handed to a caller. */
    private MemorySegment pending;
    private long pendingOffset;
    private int pendingLength;
    private boolean closed;
    private boolean frozen;
    /**
     * A snapshot has been taken and may still be taken up elsewhere. Until
     * the caller says it cannot, this connection writes nothing: a record
     * here and then one from the copy would carry the same sequence number,
     * and so the same AES-GCM nonce under the same key - two ciphertexts that
     * give away the XOR of their plaintexts and the authentication key, and
     * with it the power to forge records. Found in review, 25.09.2026.
     */
    private boolean copyOutstanding;
    private boolean endOfStream;

    /**
     * A client certificate went out and the server has not answered since -
     * the window in which a dead connection means a refused certificate.
     */
    private boolean awaitingVerdict;

    /** The server's leaf certificate, for channel binding; null after a thaw. */
    private java.security.cert.X509Certificate peerCertificate;
    private String description = "TLSv1.3";

    TlsConnection(Transport underlying, RecordStream records) {
        this.underlying = underlying;
        this.records = records;
        // Only the two messages this class sends itself go through here: a
        // KeyUpdate and a close_notify. Application data never lands in it.
        this.scratch = arena.allocate(16);
        // A post-handshake message is small; a peer announcing a huge one is
        // not doing anything this connection needs to buffer.
        this.postHandshake = new HandshakeReassembler(1 << 16);
    }

    /** Set by the handshake when it sent a client certificate. */
    void certificatePresented() {
        awaitingVerdict = true;
    }

    /** What the handshake settled on - filled in by {@link ClientHandshake}. */
    void describe(java.security.cert.X509Certificate leaf, String cipherSuite) {
        this.peerCertificate = leaf;
        this.description = "TLSv1.3 / " + cipherSuite;
    }

    /**
     * The server's certificate, or {@code null} when there is none to give.
     *
     * <p>Null in exactly two cases, and both are honest rather than
     * accidental: a server that sent no certificate, and a connection that was
     * thawed rather than handshaked here - the frozen state carries keys and
     * sequence numbers, not the certificate, because nothing needs it again
     * once the connection is running.
     */
    public java.security.cert.X509Certificate peerCertificate() {
        return peerCertificate;
    }

    /** Protocol and cipher suite. */
    public String description() {
        return description;
    }

    /**
     * Puts a different transport underneath, keeping the encryption state as
     * it is.
     *
     * <p>The keys and the record sequence numbers have no interest in which
     * descriptor carried them, so a socket rebuilt with the same sequence
     * numbers carries on encrypted. Both references have to be told: this one
     * for {@link #isOpen} and {@link #close}, and the record stream's for the
     * bytes themselves.
     */
    public void replaceTransport(Transport replacement) {
        this.underlying = replacement;
        records.replaceTransport(replacement);
    }

    @Override
    public int read(ByteBuffer into) throws IOException {
        checkUsable();
        if (!into.hasRemaining()) {
            return 0;
        }
        while (pendingLength == 0) {
            if (endOfStream) {
                return -1;
            }
            receive();
        }
        int taken = Math.min(pendingLength, into.remaining());
        MemorySegment.copy(pending, pendingOffset, MemorySegment.ofBuffer(into), 0, taken);
        into.position(into.position() + taken);
        pendingOffset += taken;
        pendingLength -= taken;
        return taken;
    }

    @Override
    public int write(ByteBuffer from) throws IOException {
        checkUsable();
        checkNoCopyOutstanding();
        int total = from.remaining();
        while (from.hasRemaining()) {
            int chunk = Math.min(from.remaining(), RecordStream.MAX_PLAINTEXT);
            try {
                records.write(RecordProtection.APPLICATION_DATA, MemorySegment.ofBuffer(from), 0,
                        chunk);
            } catch (TlsAlertException alert) {
                throw alert;
            } catch (IOException gone) {
                // The same refusal, met by the first write instead of the
                // first read - which of the two it hits is a matter of timing.
                throw ClientHandshake.refusedAfterCertificate(gone, awaitingVerdict);
            }
            from.position(from.position() + chunk);
        }
        return total;
    }

    /** Reads one record and either keeps it for the caller or acts on it here. */
    private void receive() throws IOException {
        RecordStream.Incoming record;
        try {
            record = records.next();
        } catch (TlsAlertException alert) {
            if (alert.isCloseNotify()) {
                endOfStream = true;           // the peer said goodbye; that is an end, not a fault
                return;
            }
            throw alert;
        } catch (IOException gone) {
            // The server checks a TLS 1.3 client certificate after our
            // Finished, and its alert is usually lost to the reset that
            // follows - see ClientHandshake.refusedAfterCertificate.
            throw ClientHandshake.refusedAfterCertificate(gone, awaitingVerdict);
        }
        awaitingVerdict = false;
        try {
            switch (record.contentType()) {
                case RecordProtection.APPLICATION_DATA -> {
                    pending = record.data();
                    pendingOffset = record.offset();
                    pendingLength = record.length();
                }
                case 22 -> handlePostHandshake(record);
                default -> throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                        "a record of type " + record.contentType() + " arrived on an "
                                + "established connection, where it has no meaning");
            }
        } catch (TlsProtocolException refused) {
            abort(refused.alert());
            throw refused;
        }
    }

    /**
     * RFC 8446 section 4.6: after the handshake a server may send a
     * NewSessionTicket or a KeyUpdate, and nothing else in the handshake
     * protocol.
     */
    private void handlePostHandshake(RecordStream.Incoming record) throws IOException {
        if (postHandshake.buffered() + record.length() > (1 << 16)) {
            throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                    "a post-handshake message of more than 64 KiB");
        }
        postHandshake.append(record.data(), record.offset(), record.length());
        int[] updateRequested = {-1};
        TlsProtocolException[] refused = {null};
        postHandshake.drain((type, at, length) -> {
            if (refused[0] != null) {
                return;
            }
            if (updateRequested[0] >= 0) {
                // RFC 8446 section 5.1: a KeyUpdate changes the key, and a
                // key change has to fall on a record boundary.
                refused[0] = new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                        "a handshake message followed a KeyUpdate in the same record");
                return;
            }
            switch (type) {
                case NEW_SESSION_TICKET -> {
                    // Nothing here resumes sessions; the ticket is dropped.
                }
                case KEY_UPDATE -> {
                    int value = length == 1
                            ? postHandshake.segment().get(ValueLayout.JAVA_BYTE, at) & 0xff : -1;
                    if (value != 0 && value != 1) {
                        refused[0] = new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                                length != 1
                                        ? "a KeyUpdate of " + length + " bytes; it is exactly one"
                                        : "a KeyUpdate with request_update " + value
                                                + "; only 0 and 1 exist");
                        return;
                    }
                    updateRequested[0] = value;
                }
                default -> refused[0] = new TlsProtocolException(
                        TlsAlertException.UNEXPECTED_MESSAGE,
                        "handshake message of type " + type + " on an established connection, "
                                + "where only NewSessionTicket and KeyUpdate may arrive");
            }
        });
        if (refused[0] != null) {
            throw refused[0];
        }
        if (updateRequested[0] >= 0) {
            if (postHandshake.buffered() > 0) {
                throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                        "a KeyUpdate did not end its record");
            }
            applyKeyUpdate(updateRequested[0] == 1);
        }
    }

    /**
     * We refused something the peer sent: say why, and close.
     *
     * <p>Not a {@link #close()}: that says goodbye with a {@code close_notify},
     * which is the wrong thing to tell a peer we are refusing. And no alert at
     * all while a snapshot may still be taken up elsewhere - it would be a
     * record under a nonce the copy may use again.
     */
    private void abort(int alert) {
        if (!copyOutstanding) {
            records.abort(alert);
        }
        closed = true;
        pendingLength = 0;
        postHandshake.close();
        records.close();
        arena.close();
        try {
            underlying.close();
        } catch (RuntimeException ignored) {
            // it is being closed because of the refusal; that one is the news
        }
    }

    /**
     * The peer changed its keys, so ours for reading have to follow; if it
     * asked us to change ours as well, that is a KeyUpdate of our own - sent
     * under the old key, because the peer is still reading with it.
     */
    private void applyKeyUpdate(boolean requested) throws IOException {
        records.readWith(records.readProtection().next());
        if (!requested) {
            return;
        }
        MemorySegment message = scratch.asSlice(0, Handshake.HEADER + 1);
        message.set(ValueLayout.JAVA_BYTE, 0, (byte) KEY_UPDATE);
        message.set(ValueLayout.JAVA_BYTE, 1, (byte) 0);
        message.set(ValueLayout.JAVA_BYTE, 2, (byte) 0);
        message.set(ValueLayout.JAVA_BYTE, 3, (byte) 1);
        message.set(ValueLayout.JAVA_BYTE, 4, (byte) 0);   // update_not_requested, or we would loop
        checkNoCopyOutstanding();
        records.write((byte) 22, message, 0, Handshake.HEADER + 1);
        records.writeWith(records.writeProtection().next());
    }

    // ---- moving the connection somewhere else ----------------------------

    /**
     * How many bytes {@link #freeze} needs.
     *
     * <p>Ask before allocating, and allocate a {@link space.seclume.secret.SecretScope}
     * rather than an array - what {@code freeze} writes is key material.
     */
    public int frozenLength() {
        return TlsMigration.encodedLength(records.writeProtection().hash());
    }

    /**
     * Writes this connection's encryption state out and gives up the
     * connection, <b>without closing the socket underneath and without
     * saying goodbye to the peer</b> - as far as the server is concerned
     * nothing happened, which is the entire point.
     *
     * <p>Afterwards this object is spent: reading or writing throws, and
     * {@link #close()} releases what is held here without touching the
     * transport, which now belongs to whoever continues the connection.
     *
     * <p><b>Only at a quiet moment.</b> If a record has been decrypted whose
     * bytes nobody has read yet, freezing would drop them - the peer
     * believes they were delivered, and nothing would ever ask for them
     * again. That is refused rather than risked: read what is there first,
     * then freeze. In practice a driver freezes between statements, where
     * there is nothing outstanding by construction.
     *
     * @return the number of bytes written
     */
    public int freeze(MemorySegment out, long offset) {
        if (closed || frozen) {
            throw new IllegalStateException("this connection is already "
                    + (frozen ? "frozen" : "closed"));
        }
        if (pendingLength > 0) {
            throw new IllegalStateException("there are still " + pendingLength + " bytes read "
                    + "from the peer that nobody has taken - freezing now would lose them; "
                    + "read to a quiet point first");
        }
        if (postHandshake.buffered() > 0) {
            throw new IllegalStateException("half of a post-handshake message is buffered - "
                    + "freezing now would lose it");
        }
        int length = TlsMigration.encode(out, offset,
                records.readProtection(), records.writeProtection());
        frozen = true;
        return length;
    }

    /**
     * Writes the same state {@link #freeze} writes and <b>keeps the
     * connection</b>: it goes on reading and writing, and the bytes describe
     * it exactly until the next record either way.
     *
     * <p>For a copy kept elsewhere against this process dying: taken at a
     * quiet moment, it lets another process carry on the connection from that
     * moment. Any record after it makes the copy stale - which the copy's
     * first record then shows, by failing its tag rather than being accepted.
     * The same refusals as {@code freeze}: nothing read and not yet taken,
     * no half post-handshake message.
     *
     * @return the number of bytes written
     */
    public int snapshot(MemorySegment out, long offset) {
        if (closed || frozen) {
            throw new IllegalStateException("this connection is "
                    + (frozen ? "frozen" : "closed"));
        }
        if (pendingLength > 0) {
            throw new IllegalStateException("there are still " + pendingLength + " bytes read "
                    + "from the peer that nobody has taken - a copy now would be wrong");
        }
        if (postHandshake.buffered() > 0) {
            throw new IllegalStateException("half of a post-handshake message is buffered");
        }
        int length = TlsMigration.encode(out, offset, records.readProtection(),
                records.writeProtection());
        copyOutstanding = true;
        return length;
    }

    /**
     * Every copy {@link #snapshot} made is gone or superseded - deleted
     * where it was kept, or replaced by a newer one taken before this
     * connection writes again. Until this is called the connection refuses to
     * write (see the field comment on why that is not caution but AES-GCM).
     */
    public void snapshotReleased() {
        copyOutstanding = false;
    }

    /**
     * An IOException and not a state error: to a driver this is a connection
     * it cannot write to, which it closes quietly - the one reaction that
     * sends nothing.
     */
    private void checkNoCopyOutstanding() throws IOException {
        if (copyOutstanding) {
            throw new IOException("a snapshot of this connection may still be taken "
                    + "up elsewhere, and a record written now would reuse the nonce the copy "
                    + "would write with - call snapshotReleased() once no copy can be thawed");
        }
    }

    /**
     * Carries on a connection somebody else froze, over a transport that
     * reaches the same peer.
     *
     * <p>The peer is told nothing and notices nothing: the keys and the
     * record sequence numbers continue exactly where they stopped. If any of
     * them is wrong the very next record fails its tag, which is the
     * property that makes this safe to attempt at all.
     */
    public static TlsConnection thaw(Transport transport, MemorySegment in, long offset,
            int available) {
        TlsMigration.Thawed state = TlsMigration.decode(in, offset, available);
        RecordStream records = new RecordStream(transport);
        records.readWith(state.reading());
        records.writeWith(state.writing());
        return new TlsConnection(transport, records);
    }

    @Override
    public boolean isOpen() {
        return !closed && !frozen && underlying.isOpen();
    }

    private void checkUsable() throws IOException {
        if (frozen) {
            throw new IOException("this connection was frozen and now belongs to whoever thawed "
                    + "it; using it here would send records the peer no longer expects");
        }
        if (closed) {
            throw new IOException("this connection is closed");
        }
    }

    /**
     * Lets go of this connection's own memory, and leaves the socket alone.
     *
     * <p>For the one case where a second TLS session is brought up on a
     * socket that is still in use: Oracle's TCPS listener hands the
     * connection to a server process, which starts a handshake of its own.
     * {@link #close()} would take the socket down with it and the successor
     * would have nothing to talk through - which is how that showed up, as a
     * {@code ClosedChannelException} in the middle of the second
     * ClientHello.
     *
     * <p>No goodbye is sent, deliberately: the peer that would receive it is
     * already gone, and the new one is waiting for a ClientHello.
     */
    public void discard() {
        if (closed) {
            return;
        }
        closed = true;
        postHandshake.close();
        records.close();
        arena.close();
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        if (frozen) {
            // Released, not ended: the socket and the peer's session belong to
            // whoever continues them. A close_notify here would tear down the
            // very connection that was just handed on.
            postHandshake.close();
            records.close();
            arena.close();
            return;
        }
        if (copyOutstanding) {
            // Not even a goodbye: a close_notify is a record under a nonce the
            // copy may still use.
            postHandshake.close();
            records.close();
            arena.close();
            underlying.close();
            return;
        }
        try {
            MemorySegment goodbye = scratch.asSlice(0, 2);
            goodbye.set(ValueLayout.JAVA_BYTE, 0, (byte) TlsAlertException.WARNING);
            goodbye.set(ValueLayout.JAVA_BYTE, 1, (byte) TlsAlertException.CLOSE_NOTIFY);
            records.write((byte) 21, goodbye, 0, 2);
        } catch (IOException | RuntimeException ignored) {
            // Saying goodbye is a courtesy; a peer that has already gone cannot be told.
        }
        postHandshake.close();
        records.close();
        arena.close();
        underlying.close();
    }
}
