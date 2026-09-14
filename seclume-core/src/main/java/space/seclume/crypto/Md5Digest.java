package space.seclume.crypto;

import java.lang.foreign.MemorySegment;

/**
 * MD5 (RFC 1321) off-heap.
 *
 * <p>Needed for PostgreSQL's {@code md5} authentication and MySQL's
 * {@code mysql_native_password}. Broken as a hash, unavoidable as part of a
 * protocol.
 */
final class Md5Digest extends BlockDigest {

    /** K[i] = floor(2^32 * abs(sin(i + 1))) - public constants. */
    private static final int[] K = new int[64];
    private static final int[] S = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    };

    static {
        for (int i = 0; i < 64; i++) {
            K[i] = (int) (long) (Math.abs(Math.sin(i + 1.0)) * 4294967296.0);
        }
    }

    /** Four chaining words. */
    private static final long STATE_BYTES = 16;

    Md5Digest() {
        super(64, 8, STATE_BYTES);
    }

    @Override
    public int digestLength() {
        return 16;
    }

    @Override
    void initState() {
        state.set(LE_INT, 0, 0x67452301);
        state.set(LE_INT, 4, 0xefcdab89);
        state.set(LE_INT, 8, 0x98badcfe);
        state.set(LE_INT, 12, 0x10325476);
    }

    /** MD5 appends the bit length little-endian, unlike SHA. */
    @Override
    void writeLength(int at, long bitCount) {
        block.set(LE_LONG, at, bitCount);
    }

    @Override
    void compress(MemorySegment data, long offset) {
        int a = state.get(LE_INT, 0);
        int b = state.get(LE_INT, 4);
        int c = state.get(LE_INT, 8);
        int d = state.get(LE_INT, 12);
        final int a0 = a;
        final int b0 = b;
        final int c0 = c;
        final int d0 = d;

        for (int i = 0; i < 64; i++) {
            int f;
            int g;
            if (i < 16) {
                f = (b & c) | (~b & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | (~d & c);
                g = (5 * i + 1) & 15;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) & 15;
            } else {
                f = c ^ (b | ~d);
                g = (7 * i) & 15;
            }
            int word = data.get(LE_INT, offset + g * 4L);
            f = f + a + K[i] + word;
            a = d;
            d = c;
            c = b;
            b = b + Integer.rotateLeft(f, S[i]);
        }

        state.set(LE_INT, 0, a0 + a);
        state.set(LE_INT, 4, b0 + b);
        state.set(LE_INT, 8, c0 + c);
        state.set(LE_INT, 12, d0 + d);
    }

    @Override
    void writeResult(MemorySegment out, long offset) {
        MemorySegment.copy(state, 0, out, offset, 16);
    }
}
