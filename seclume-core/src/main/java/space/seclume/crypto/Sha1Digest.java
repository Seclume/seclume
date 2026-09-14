package space.seclume.crypto;

import java.lang.foreign.MemorySegment;

/**
 * SHA-1 (FIPS 180-4) off-heap.
 *
 * <p>Needed for MySQL's {@code mysql_native_password} and Oracle's O5LOGON
 * verifier for 11g.
 */
final class Sha1Digest extends BlockDigest {

    private static final long H_OFFSET = 0;
    private static final long W_OFFSET = 20;
    private static final long STATE_BYTES = W_OFFSET + 80 * 4L;

    Sha1Digest() {
        super(64, 8, STATE_BYTES);
    }

    @Override
    public int digestLength() {
        return 20;
    }

    @Override
    void initState() {
        state.set(BE_INT, H_OFFSET, 0x67452301);
        state.set(BE_INT, H_OFFSET + 4, 0xefcdab89);
        state.set(BE_INT, H_OFFSET + 8, 0x98badcfe);
        state.set(BE_INT, H_OFFSET + 12, 0x10325476);
        state.set(BE_INT, H_OFFSET + 16, 0xc3d2e1f0);
    }

    @Override
    void compress(MemorySegment data, long offset) {
        for (int i = 0; i < 16; i++) {
            state.set(BE_INT, W_OFFSET + i * 4L, data.get(BE_INT, offset + i * 4L));
        }
        for (int i = 16; i < 80; i++) {
            int w = state.get(BE_INT, W_OFFSET + (i - 3) * 4L)
                    ^ state.get(BE_INT, W_OFFSET + (i - 8) * 4L)
                    ^ state.get(BE_INT, W_OFFSET + (i - 14) * 4L)
                    ^ state.get(BE_INT, W_OFFSET + (i - 16) * 4L);
            state.set(BE_INT, W_OFFSET + i * 4L, Integer.rotateLeft(w, 1));
        }

        int a = state.get(BE_INT, H_OFFSET);
        int b = state.get(BE_INT, H_OFFSET + 4);
        int c = state.get(BE_INT, H_OFFSET + 8);
        int d = state.get(BE_INT, H_OFFSET + 12);
        int e = state.get(BE_INT, H_OFFSET + 16);

        for (int i = 0; i < 80; i++) {
            int f;
            int k;
            if (i < 20) {
                f = (b & c) | (~b & d);
                k = 0x5a827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ed9eba1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8f1bbcdc;
            } else {
                f = b ^ c ^ d;
                k = 0xca62c1d6;
            }
            int temp = Integer.rotateLeft(a, 5) + f + e + k + state.get(BE_INT, W_OFFSET + i * 4L);
            e = d;
            d = c;
            c = Integer.rotateLeft(b, 30);
            b = a;
            a = temp;
        }

        state.set(BE_INT, H_OFFSET, state.get(BE_INT, H_OFFSET) + a);
        state.set(BE_INT, H_OFFSET + 4, state.get(BE_INT, H_OFFSET + 4) + b);
        state.set(BE_INT, H_OFFSET + 8, state.get(BE_INT, H_OFFSET + 8) + c);
        state.set(BE_INT, H_OFFSET + 12, state.get(BE_INT, H_OFFSET + 12) + d);
        state.set(BE_INT, H_OFFSET + 16, state.get(BE_INT, H_OFFSET + 16) + e);
    }

    @Override
    void writeResult(MemorySegment out, long offset) {
        MemorySegment.copy(state, H_OFFSET, out, offset, 20);
    }
}
