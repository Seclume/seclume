package space.seclume.crypto;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;

/**
 * GHASH of GCM (NIST SP 800-38D), branch-free and table-free.
 *
 * <p>The authenticator of AES-GCM: a multiplication in GF(2^128) of every
 * sixteen-byte block against a key that is itself AES applied to zero. It is
 * needed here because TLS 1.3 requires AEAD and this project cannot use the
 * JCA's - measured, not argued: {@code AeadKeyTest} finds the traffic key in a
 * heap dump when the JCA holds it, and {@code SecretKeySpec} cannot be wiped.
 *
 * <p><b>Why it is written the slow way.</b> Every fast GHASH multiplies through
 * a precomputed table indexed by the data, and a table lookup indexed by secret
 * data is a cache-timing side channel - the attack on table-driven AES is the
 * textbook case. So this shifts bit by bit, 128 iterations a block, and the
 * choice at each bit is made by a <b>mask</b> rather than by a branch:
 * {@code -(bit)} is all-ones or all-zeroes, and the operation happens either
 * way with the same instructions and the same memory accesses.
 *
 * <p>That costs perhaps an order of magnitude against a table version. The
 * comparison that matters is not against a table but against the alternative
 * this project actually has, which is putting the key on the heap; and against
 * the round trip a record is sent over, which is microseconds.
 *
 * <p>The state is two {@code long}s rather than a segment on purpose: the
 * running hash is not the key. The key is, and it stays where the caller put
 * it.
 */
public final class Ghash implements AutoCloseable {

    /** The reduction polynomial of GF(2^128), x^128 + x^7 + x^2 + x + 1. */
    private static final long R = 0xe100000000000000L;

    private final long keyHigh;
    private final long keyLow;
    private long high;
    private long low;

    /**
     * @param key the sixteen-byte hash subkey H, big endian as GCM defines it
     */
    public Ghash(MemorySegment key, long offset) {
        this.keyHigh = beLong(key, offset);
        this.keyLow = beLong(key, offset + 8);
    }

    /** Feeds one sixteen-byte block. */
    public void update(MemorySegment data, long offset) {
        high ^= beLong(data, offset);
        low ^= beLong(data, offset + 8);
        multiply();
    }

    /**
     * Feeds {@code length} bytes, padding the last block with zeroes.
     *
     * <p>Padding rather than refusing: GCM hashes the additional data and the
     * ciphertext each zero-padded to a block boundary, and the lengths that go
     * in at the end are what keeps that unambiguous.
     */
    public void update(MemorySegment data, long offset, long length) {
        long at = 0;
        while (length - at >= 16) {
            update(data, offset + at);
            at += 16;
        }
        long rest = length - at;
        if (rest > 0) {
            long tailHigh = 0;
            long tailLow = 0;
            for (int i = 0; i < 8 && i < rest; i++) {
                tailHigh |= (data.get(ValueLayout.JAVA_BYTE, offset + at + i) & 0xffL)
                        << (56 - 8 * i);
            }
            for (int i = 8; i < 16 && i < rest; i++) {
                tailLow |= (data.get(ValueLayout.JAVA_BYTE, offset + at + i) & 0xffL)
                        << (56 - 8 * (i - 8));
            }
            high ^= tailHigh;
            low ^= tailLow;
            multiply();
        }
    }

    /** The two length words GCM ends with, in bits. */
    public void updateLengths(long aadBytes, long dataBytes) {
        high ^= aadBytes * 8;
        low ^= dataBytes * 8;
        multiply();
    }

    /** Writes the sixteen-byte result. */
    public void doFinal(MemorySegment out, long offset) {
        putBeLong(out, offset, high);
        putBeLong(out, offset + 8, low);
    }

    /**
     * Z = Z x H in GF(2^128), the right-shift algorithm of SP 800-38D.
     *
     * <p>No branch depends on a bit of the data, and nothing is indexed by one.
     * The two places where a naive version would branch - „is this bit set"
     * and „did a one shift out" - are both turned into a mask of all ones or
     * all zeroes and then applied unconditionally.
     */
    private void multiply() {
        long zHigh = 0;
        long zLow = 0;
        long vHigh = keyHigh;
        long vLow = keyLow;
        long xHigh = high;
        long xLow = low;

        for (int i = 0; i < 64; i++) {
            long mask = -((xHigh >>> (63 - i)) & 1L);
            zHigh ^= vHigh & mask;
            zLow ^= vLow & mask;
            long carry = -(vLow & 1L);
            vLow = (vLow >>> 1) | (vHigh << 63);
            vHigh = (vHigh >>> 1) ^ (R & carry);
        }
        for (int i = 0; i < 64; i++) {
            long mask = -((xLow >>> (63 - i)) & 1L);
            zHigh ^= vHigh & mask;
            zLow ^= vLow & mask;
            long carry = -(vLow & 1L);
            vLow = (vLow >>> 1) | (vHigh << 63);
            vHigh = (vHigh >>> 1) ^ (R & carry);
        }
        high = zHigh;
        low = zLow;
    }

    private static long beLong(MemorySegment segment, long offset) {
        return segment.get(ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.BIG_ENDIAN),
                offset);
    }

    private static void putBeLong(MemorySegment segment, long offset, long value) {
        segment.set(ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.BIG_ENDIAN), offset,
                value);
    }

    /** Forgets the running hash. The key belongs to the caller. */
    @Override
    public void close() {
        high = 0;
        low = 0;
    }
}
