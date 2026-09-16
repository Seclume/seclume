package space.seclume.tls;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.crypto.Digest;
import space.seclume.crypto.HashAlgorithm;

/**
 * The running hash over the handshake messages, which the key schedule needs
 * at several points while the handshake is still going on.
 *
 * <p>Every {@code Derive-Secret} in TLS 1.3 takes a transcript hash as its
 * context: the handshake traffic secrets are derived over ClientHello through
 * ServerHello, the application traffic secrets over everything up to the
 * server's Finished, the resumption secret over everything up to the client's.
 * So this has to yield a digest at a point in the middle <b>without</b> ending
 * the hash.
 *
 * <p><b>Why it keeps the bytes instead of cloning a digest.</b> The obvious
 * implementation copies the digest state and finishes the copy, and that is
 * what a stack with a cloneable digest does. {@link Digest} here has no
 * {@code copy}, and adding one would mean touching five implementations to
 * serve one caller. Keeping the transcript instead costs a re-hash per query -
 * microseconds over a few kilobytes, against a handshake that is one network
 * round trip - and the buffer holds no key material: handshake messages are
 * the one part of TLS that carries none. If a third caller ever wants a
 * snapshot, the copy belongs in {@code Digest} and this class should follow.
 *
 * <p>The buffer is native and is wiped when it grows and when it is closed,
 * which is habit rather than necessity here - the certificate and the Finished
 * are not secrets - but the habit is the point.
 */
public final class TranscriptHash implements AutoCloseable {

    /** The pseudo-message a HelloRetryRequest transcript starts with. */
    private static final byte MESSAGE_HASH = (byte) 254;
    private static final int INITIAL = 1024;

    private final HashAlgorithm algorithm;
    private Arena arena = Arena.ofShared();
    private MemorySegment buffer;
    private int length;

    public TranscriptHash(HashAlgorithm algorithm) {
        this.algorithm = algorithm;
        this.buffer = arena.allocate(INITIAL);
    }

    /** Appends one handshake message - header included, as it was on the wire. */
    public void update(MemorySegment data, long offset, int count) {
        if (count <= 0) {
            return;
        }
        ensure(length + count);
        MemorySegment.copy(data, offset, buffer, length, count);
        length += count;
    }

    /**
     * The hash of everything so far, the transcript left intact.
     *
     * @param out receives {@link HashAlgorithm#digestLength()} bytes
     */
    public void current(MemorySegment out, long outOffset) {
        try (Digest digest = algorithm.newDigest()) {
            digest.update(buffer, 0, length);
            digest.digest(out, outOffset);
        }
    }

    /** How many bytes of handshake are in the transcript. */
    public int length() {
        return length;
    }

    /**
     * Replaces the transcript with the {@code message_hash} form a
     * HelloRetryRequest demands (RFC 8446, section 4.4.1).
     *
     * <p>When the server refuses the client's key share and asks for another,
     * the transcript does <b>not</b> simply continue. Everything so far - which
     * is exactly the first ClientHello - is replaced by a synthetic message of
     * type 254 carrying its hash, and the HelloRetryRequest and second
     * ClientHello follow that. A client that just keeps appending computes a
     * transcript nobody else has and derives handshake keys that open nothing;
     * the symptom is a connection that dies right after the second ServerHello,
     * which reads like a key-exchange problem rather than a bookkeeping one.
     *
     * <p>Call this after the first ClientHello and before the
     * HelloRetryRequest goes in.
     */
    public void substituteWithMessageHash() {
        int digestLength = algorithm.digestLength();
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment digest = scratch.allocate(digestLength);
            current(digest, 0);
            buffer.asSlice(0, length).fill((byte) 0);
            length = 0;
            ensure(Handshake.HEADER + digestLength);
            buffer.set(ValueLayout.JAVA_BYTE, 0, MESSAGE_HASH);
            buffer.set(ValueLayout.JAVA_BYTE, 1, (byte) 0);
            buffer.set(ValueLayout.JAVA_BYTE, 2, (byte) (digestLength >>> 8));
            buffer.set(ValueLayout.JAVA_BYTE, 3, (byte) digestLength);
            MemorySegment.copy(digest, 0, buffer, Handshake.HEADER, digestLength);
            length = Handshake.HEADER + digestLength;
        }
    }

    private void ensure(int needed) {
        if (needed <= buffer.byteSize()) {
            return;
        }
        long grown = buffer.byteSize();
        while (grown < needed) {
            grown *= 2;
        }
        Arena replacement = Arena.ofShared();
        MemorySegment bigger = replacement.allocate(grown);
        if (length > 0) {
            MemorySegment.copy(buffer, 0, bigger, 0, length);
        }
        buffer.fill((byte) 0);
        arena.close();
        arena = replacement;
        buffer = bigger;
    }

    @Override
    public void close() {
        buffer.fill((byte) 0);
        arena.close();
        length = 0;
    }
}
