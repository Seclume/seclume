package space.seclume.tls;

import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;

import space.seclume.internal.Transport;

/**
 * Records on and off the wire, with whatever protection is currently in
 * force - the one place that knows whether bytes are still in the clear.
 *
 * <p>A TLS connection changes keys twice while it is being set up (plaintext,
 * then handshake keys, then application keys) and possibly again later on a
 * KeyUpdate. Every one of those switches is a place to send a record under
 * the wrong key, which the peer answers with {@code bad_record_mac} and no
 * further explanation. Keeping the current pair of {@link RecordProtection}s
 * in one object, with the switch as a method call, is what makes that hard
 * to get wrong - the handshake and the finished connection then share this
 * rather than each doing their own framing.
 *
 * <p>Three shapes it hides from its callers:
 *
 * <ul>
 *   <li><b>ChangeCipherSpec is swallowed.</b> TLS 1.3 has no such thing; the
 *       record exists only so that middleboxes watching for a TLS 1.2
 *       handshake see what they expect. It is not encrypted even after
 *       encryption starts, and it is not part of the transcript, so it is
 *       dropped before anything else looks at it;
 *   <li><b>the real content type lives inside the encryption.</b> Every
 *       protected record claims to be {@code application_data} on the wire,
 *       so what a caller gets back is the type from inside, not the header;
 *   <li><b>an alert is raised rather than returned.</b> A caller that has to
 *       remember to check for one will eventually not, and the failure then
 *       looks like a protocol bug instead of the peer's stated reason.
 * </ul>
 */
final class RecordStream implements AutoCloseable {

    /** A protected record may exceed the plaintext limit by a tag and the inner type. */
    static final int MAX_CIPHERTEXT = (1 << 14) + 256;
    static final int MAX_PLAINTEXT = 1 << 14;

    /** What one record turned out to carry. */
    record Incoming(int contentType, MemorySegment data, long offset, int length) {
    }

    /**
     * Not final: when a connection's socket is rebuilt beneath it - a move
     * within one process - this is the reference that would otherwise keep
     * reading through the closed descriptor.
     */
    private Transport transport;
    private final Arena arena = Arena.ofShared();
    private final MemorySegment incoming;
    private final MemorySegment opened;
    private final MemorySegment outgoing;
    private RecordProtection reading;
    private RecordProtection writing;
    private boolean firstRecord = true;

    RecordStream(Transport transport) {
        this.transport = transport;
        this.incoming = arena.allocate(RecordProtection.HEADER + MAX_CIPHERTEXT);
        this.opened = arena.allocate(MAX_CIPHERTEXT);
        this.outgoing = arena.allocate(RecordProtection.HEADER + MAX_CIPHERTEXT);
    }

    /** Takes over the keys for one direction; the old ones are closed. */
    void readWith(RecordProtection protection) {
        if (reading != null) {
            reading.close();
        }
        reading = protection;
    }

    void writeWith(RecordProtection protection) {
        if (writing != null) {
            writing.close();
        }
        writing = protection;
    }

    /** Puts a different transport underneath, keeping both keys as they are. */
    void replaceTransport(Transport replacement) {
        this.transport = replacement;
    }

    RecordProtection readProtection() {
        return reading;
    }

    RecordProtection writeProtection() {
        return writing;
    }

    /**
     * The next record that carries something, opened if it was protected.
     *
     * <p>The returned view is only valid until the next call - it points into
     * this object's own buffer, which is the point: a record is read, used
     * and forgotten without a copy.
     */
    Incoming next() throws IOException {
        while (true) {
            readFully(RecordProtection.HEADER, 0);
            int type = byteAt(incoming, 0);
            int length = (byteAt(incoming, 3) << 8) | byteAt(incoming, 4);
            if (length > MAX_CIPHERTEXT) {
                throw new IOException("a record announced " + length + " bytes, more than TLS "
                        + "allows (" + MAX_CIPHERTEXT + ") - this is not a TLS 1.3 server");
            }
            readFully(length, RecordProtection.HEADER);

            if (type == 20) {
                continue;                     // ChangeCipherSpec: legacy noise, never in the transcript
            }
            if (reading == null) {
                if (type == 21) {
                    throw alert(incoming, RecordProtection.HEADER, length);
                }
                return new Incoming(type, incoming, RecordProtection.HEADER, length);
            }
            if (type != 23) {
                throw new IOException("a record of type " + type + " arrived after encryption "
                        + "started, where only application_data may appear");
            }
            RecordProtection.Opened result =
                    reading.open(incoming, 0, RecordProtection.HEADER + length, opened, 0);
            if (result == null) {
                throw new IOException("a record did not authenticate - the key, the sequence "
                        + "number or the bytes themselves are wrong");
            }
            if (result.contentType() == 21) {
                throw alert(opened, 0, result.length());
            }
            return new Incoming(result.contentType(), opened, 0, result.length());
        }
    }

    /** Writes one record, protected if keys are in force, split by the caller if too long. */
    void write(byte contentType, MemorySegment data, long offset, int length) throws IOException {
        if (length > MAX_PLAINTEXT) {
            throw new IllegalArgumentException("a record holds at most " + MAX_PLAINTEXT
                    + " bytes, not " + length);
        }
        int total;
        if (writing == null) {
            outgoing.set(ValueLayout.JAVA_BYTE, 0, contentType);
            outgoing.set(ValueLayout.JAVA_BYTE, 1, (byte) 0x03);
            // The very first record says TLS 1.0 and every later one TLS 1.2, both lies
            // the specification requires so that old middleboxes recognise the shape.
            outgoing.set(ValueLayout.JAVA_BYTE, 2, (byte) (firstRecord ? 0x01 : 0x03));
            outgoing.set(ValueLayout.JAVA_BYTE, 3, (byte) (length >>> 8));
            outgoing.set(ValueLayout.JAVA_BYTE, 4, (byte) length);
            MemorySegment.copy(data, offset, outgoing, RecordProtection.HEADER, length);
            total = RecordProtection.HEADER + length;
        } else {
            total = writing.seal(contentType, data, offset, length, outgoing, 0);
        }
        firstRecord = false;
        writeFully(total);
    }

    /**
     * The ChangeCipherSpec a client sends for the benefit of middleboxes -
     * one byte, always in the clear, ignored by any TLS 1.3 peer.
     */
    void writeChangeCipherSpec() throws IOException {
        MemorySegment one = outgoing.asSlice(RecordProtection.HEADER + MAX_CIPHERTEXT - 1, 1);
        one.set(ValueLayout.JAVA_BYTE, 0, (byte) 1);
        RecordProtection saved = writing;
        writing = null;                       // it is never encrypted, whatever else is in force
        try {
            write((byte) 20, one, 0, 1);
        } finally {
            writing = saved;
        }
    }

    private TlsAlertException alert(MemorySegment data, long offset, int length) {
        if (length < 2) {
            return new TlsAlertException(TlsAlertException.FATAL, -1);
        }
        return new TlsAlertException(byteAt(data, offset), byteAt(data, offset + 1));
    }

    private void readFully(int count, long into) throws IOException {
        ByteBuffer buffer = incoming.asByteBuffer().position((int) into).limit((int) into + count);
        while (buffer.hasRemaining()) {
            int read = transport.read(buffer);
            if (read < 0) {
                throw new EOFException("the connection ended in the middle of a TLS record - "
                        + count + " bytes were expected, " + (count - buffer.remaining())
                        + " arrived");
            }
        }
    }

    private void writeFully(int count) throws IOException {
        ByteBuffer buffer = outgoing.asByteBuffer().position(0).limit(count);
        while (buffer.hasRemaining()) {
            transport.write(buffer);
        }
    }

    private static int byteAt(MemorySegment data, long offset) {
        return data.get(ValueLayout.JAVA_BYTE, offset) & 0xff;
    }

    @Override
    public void close() {
        if (reading != null) {
            reading.close();
            reading = null;
        }
        if (writing != null) {
            writing.close();
            writing = null;
        }
        arena.close();
    }
}
