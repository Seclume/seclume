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
 *       after the switch.
 * </ul>
 *
 * <p>Both traffic secrets stay off-heap for the life of the connection, in
 * the {@link RecordProtection}s this owns - which is the whole reason this
 * class exists rather than an {@code SSLEngine}.
 */
public final class TlsConnection implements Transport {

    private static final int NEW_SESSION_TICKET = Handshake.NEW_SESSION_TICKET;
    private static final int KEY_UPDATE = 24;

    private final Transport underlying;
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
    private boolean endOfStream;

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
        int total = from.remaining();
        while (from.hasRemaining()) {
            int chunk = Math.min(from.remaining(), RecordStream.MAX_PLAINTEXT);
            records.write(RecordProtection.APPLICATION_DATA, MemorySegment.ofBuffer(from), 0, chunk);
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
        }
        switch (record.contentType()) {
            case RecordProtection.APPLICATION_DATA -> {
                pending = record.data();
                pendingOffset = record.offset();
                pendingLength = record.length();
            }
            case 22 -> handlePostHandshake(record);
            default -> throw new IOException("a record of type " + record.contentType()
                    + " arrived on an established connection, where it has no meaning");
        }
    }

    private void handlePostHandshake(RecordStream.Incoming record) throws IOException {
        postHandshake.append(record.data(), record.offset(), record.length());
        int[] updateRequested = {-1};
        postHandshake.drain((type, at, length) -> {
            if (type == KEY_UPDATE && length >= 1) {
                updateRequested[0] =
                        postHandshake.segment().get(ValueLayout.JAVA_BYTE, at) & 0xff;
            }
            // NewSessionTicket and anything else: nothing here uses it.
        });
        if (updateRequested[0] >= 0) {
            applyKeyUpdate(updateRequested[0] == 1);
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
     * Carries on a connection somebody else froze, over a transport that
      * reaches the same peer - the far end of a handover,
     * or of this project's own TCP stack having moved the socket.
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
