package space.seclume.tls;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * Turns a stream of decrypted handshake bytes - each chunk the plaintext of
 * one opened TLS record - back into complete handshake messages.
 *
 * <p>Nothing here guarantees a message arrives in one record. A server's
 * second flight (EncryptedExtensions, Certificate, CertificateVerify, Finished)
 * commonly packs several messages into one record, and equally a single large
 * Certificate message is commonly split across several - the two shapes
 * {@link Handshake#messages} on its own cannot tell apart from a truncated
 * message. This is the piece that has to sit in front of it: it buffers
 * whatever is incomplete and hands {@link Handshake#messages} only whole
 * messages, one call to {@link #append} at a time, however the peer chose to
 * split them.
 *
 * <p>The buffer is bounded by construction. Nothing stops a peer from
 * announcing a message of the maximum length TLS's three-byte field allows
 * (16 MiB) and never sending the rest - without a limit that is an easy way to
 * make a client hold arbitrary amounts of memory for a connection that will
 * never complete. {@link #append} throws once the {@linkplain #HandshakeReassembler
 * configured cap} is exceeded, the same shape as the bounded reads elsewhere
 * in this project (TCP options, the Oracle NS channel): a named limit and a
 * clear failure rather than an allocator that keeps growing until it cannot.
 *
 * <p>Handshake messages carry no secret - the certificate and the Finished
 * value are not key material - so unlike {@link TranscriptHash} this buffer is
 * not wiped; it is freed like ordinary memory.
 */
public final class HandshakeReassembler implements AutoCloseable {

    private final int maxLength;
    private Arena arena = Arena.ofShared();
    private MemorySegment buffer;
    private int length;

    /**
     * @param maxLength the most bytes this will ever hold buffered at once -
     *                  bigger than the largest message a caller expects to see,
     *                  smaller than what an attacker should be allowed to force
     *                  it to allocate
     */
    public HandshakeReassembler(int maxLength) {
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxLength must be positive");
        }
        this.maxLength = maxLength;
        this.buffer = arena.allocate(Math.min(maxLength, 4096));
    }

    /** Appends one record's worth of decrypted handshake bytes. */
    public void append(MemorySegment data, long offset, int count) {
        if (count <= 0) {
            return;
        }
        if (length + count > maxLength) {
            throw new IllegalStateException("handshake reassembly buffer exceeded " + maxLength
                    + " bytes - a message this large, or this incomplete, is refused rather than "
                    + "buffered without limit");
        }
        ensure(length + count);
        MemorySegment.copy(data, offset, buffer, length, count);
        length += count;
    }

    /**
     * Hands every complete message currently buffered to {@code reader}, in
     * order, then discards them - what is left is exactly the tail of a
     * message still in flight, ready for the next {@link #append}.
     *
     * <p>A message is read out to {@code reader} in place, inside this
     * object's own buffer - the same "read in place" shape as
     * {@link Handshake#messages}. It is only valid until the next call to
     * {@link #append} or {@link #drain}.
     */
    public void drain(Handshake.Reader reader) {
        int consumed = 0;
        while (length - consumed >= Handshake.HEADER) {
            int total = Handshake.totalLength(buffer, consumed);
            if (total <= 0 || consumed + total > length) {
                break;                       // the rest is an incomplete message
            }
            reader.message(Handshake.type(buffer, consumed), consumed + Handshake.HEADER,
                    total - Handshake.HEADER);
            consumed += total;
        }
        if (consumed == 0) {
            return;
        }
        int remaining = length - consumed;
        if (remaining > 0) {
            MemorySegment.copy(buffer, consumed, buffer, 0, remaining);
        }
        length = remaining;
    }

    /** Bytes currently buffered - a complete message not yet drained plus any partial tail. */
    public int buffered() {
        return length;
    }

    /**
     * The buffer {@link #drain}'s offsets point into. A reader reads a message's
     * body at {@code (at, length)} from here, the same shape {@link Handshake#messages}
     * uses for a single record - exposed because {@link Handshake.Reader} carries no
     * segment of its own, only offsets into whatever the caller passed it.
     */
    public MemorySegment segment() {
        return buffer;
    }

    private void ensure(int needed) {
        if (needed <= buffer.byteSize()) {
            return;
        }
        long grown = buffer.byteSize();
        while (grown < needed) {
            grown *= 2;
        }
        grown = Math.min(grown, maxLength);
        Arena replacement = Arena.ofShared();
        MemorySegment bigger = replacement.allocate(grown);
        if (length > 0) {
            MemorySegment.copy(buffer, 0, bigger, 0, length);
        }
        arena.close();
        arena = replacement;
        buffer = bigger;
    }

    @Override
    public void close() {
        arena.close();
        length = 0;
    }
}
