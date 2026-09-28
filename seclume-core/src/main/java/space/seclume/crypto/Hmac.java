package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * HMAC (RFC 2104) off-heap.
 *
 * <p>With SCRAM, {@code caching_sha2_password} and PBKDF2 the key is the
 * password itself or directly derived from it. That rules out both
 * {@link javax.crypto.Mac} and {@link javax.crypto.spec.SecretKeySpec}: each
 * takes the key as a {@code byte[]} and copies it again internally.
 *
 * <p>The hash state after the padded key stays in memory for the lifetime of
 * the object - that is deliberate, so PBKDF2 does not have to hash the key
 * again on each of its thousands of rounds - but off-heap, and zeroed on
 * close.
 */
public final class Hmac implements AutoCloseable {

    private final Arena arena = Arena.ofConfined();
    private final BlockDigest inner;
    private final BlockDigest outer;
    /**
     * The chaining values after the padded key block, inner and outer. Every
     * message under this key starts from them, so they are computed once and
     * restored - instead of compressing K0 ^ ipad and K0 ^ opad again on each
     * {@link #doFinal}. In PBKDF2 that is half the work of every round.
     * Derived from the key, so off-heap and zeroed on close like the pads
     * they replace.
     */
    private final MemorySegment innerChain;
    private final MemorySegment outerChain;
    private final long innerCount;
    private final long outerCount;
    private final MemorySegment scratch;
    private final int digestLength;
    private boolean closed;

    /** HMAC with the key {@code key[keyOffset..keyOffset+keyLength)}. */
    public Hmac(HashAlgorithm algorithm, MemorySegment key, long keyOffset, long keyLength) {
        int blockLength = algorithm.blockLength();
        this.digestLength = algorithm.digestLength();
        this.inner = (BlockDigest) algorithm.newDigest();
        this.outer = (BlockDigest) algorithm.newDigest();
        this.innerChain = arena.allocate(inner.chainLength());
        this.outerChain = arena.allocate(outer.chainLength());
        this.scratch = arena.allocate(digestLength);

        // K0: longer keys are hashed, shorter ones padded with zeroes.
        MemorySegment k0 = arena.allocate(blockLength);
        MemorySegment pad = arena.allocate(blockLength);
        try {
            if (keyLength > blockLength) {
                algorithm.hash(key, keyOffset, keyLength, k0, 0);
            } else {
                MemorySegment.copy(key, keyOffset, k0, 0, keyLength);
            }
            xor(k0, (byte) 0x36, pad, blockLength);
            inner.update(pad);
            this.innerCount = inner.saveChain(innerChain);
            xor(k0, (byte) 0x5c, pad, blockLength);
            outer.update(pad);
            this.outerCount = outer.saveChain(outerChain);
        } finally {
            k0.fill((byte) 0);
            pad.fill((byte) 0);
        }
    }

    private static void xor(MemorySegment k0, byte value, MemorySegment pad, int length) {
        for (int i = 0; i < length; i++) {
            pad.set(ValueLayout.JAVA_BYTE, i, (byte) (k0.get(ValueLayout.JAVA_BYTE, i) ^ value));
        }
    }

    /** HMAC over the whole key segment. */
    public Hmac(HashAlgorithm algorithm, MemorySegment key) {
        this(algorithm, key, 0, key.byteSize());
    }

    public int macLength() {
        return digestLength;
    }

    public void update(MemorySegment data, long offset, long length) {
        checkOpen();
        inner.update(data, offset, length);
    }

    public void update(MemorySegment data) {
        update(data, 0, data.byteSize());
    }

    /** A single byte - protocols like to append counters. */
    public void update(byte value) {
        checkOpen();
        MemorySegment one = scratch.asSlice(0, 1);
        one.set(ValueLayout.JAVA_BYTE, 0, value);
        inner.update(one, 0, 1);
        one.set(ValueLayout.JAVA_BYTE, 0, (byte) 0);
    }

    /**
     * Finishes the MAC and writes it into {@code out}. Afterwards the object
     * is back at the start and can be used again with the same key.
     */
    public void doFinal(MemorySegment out, long offset) {
        checkOpen();
        try {
            inner.digest(scratch, 0);
            outer.restoreChain(outerChain, outerCount);
            outer.update(scratch, 0, digestLength);
            outer.digest(out, offset);
        } finally {
            scratch.fill((byte) 0);
            inner.restoreChain(innerChain, innerCount);
        }
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        innerChain.fill((byte) 0);
        outerChain.fill((byte) 0);
        scratch.fill((byte) 0);
        inner.close();
        outer.close();
        arena.close();
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("this HMAC is closed - its key was wiped, build a new one");
        }
    }
}
