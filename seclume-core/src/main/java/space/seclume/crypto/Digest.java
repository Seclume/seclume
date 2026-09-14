package space.seclume.crypto;

import java.lang.foreign.MemorySegment;

/**
 * A hash that works exclusively on off-heap memory.
 *
 * <p>Why not {@link java.security.MessageDigest}: the JCA takes its input as
 * {@code byte[]} and copies intermediate state into further heap arrays. As
 * soon as the password itself is hashed - and all four database handshakes do
 * exactly that - it sits in the heap and shows up in a heap dump. This
 * interface therefore accepts only {@link MemorySegment} and keeps its own
 * state (chaining value, message schedule, partial block) off-heap as well.
 *
 * <p>Not thread-safe: a digest belongs to whoever created it. {@link #close()}
 * zeroes the entire internal state and releases it; that belongs in a
 * {@code try}-with-resources.
 */
public interface Digest extends AutoCloseable {

    /** Length of the result in bytes. */
    int digestLength();

    /** Block size of the algorithm in bytes - HMAC needs it. */
    int blockLength();

    /** Feeds {@code length} bytes starting at {@code offset} into the hash. */
    void update(MemorySegment data, long offset, long length);

    /** Feeds the whole segment in. */
    default void update(MemorySegment data) {
        update(data, 0, data.byteSize());
    }

    /**
     * Finishes the hash and writes {@link #digestLength()} bytes into
     * {@code out} at {@code offset}. Afterwards the digest is back in its
     * initial state and can be used again.
     */
    void digest(MemorySegment out, long offset);

    /** Discards what has been fed in so far and starts over. */
    void reset();

    /** Zeroes the internal state and releases the memory. */
    @Override
    void close();
}
