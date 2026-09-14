package space.seclume.crypto;

import java.lang.foreign.MemorySegment;

/**
 * SHA-256 (FIPS 180-4) off-heap.
 *
 * <p>The workhorse: PostgreSQL SCRAM-SHA-256, MySQL
 * {@code caching_sha2_password}, MariaDB {@code parsec}, TDS channel binding.
 */
final class Sha256Digest extends BlockDigest {

    private static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    private static final long H_OFFSET = 0;
    private static final long W_OFFSET = 32;
    private static final long STATE_BYTES = W_OFFSET + 64 * 4L;

    Sha256Digest() {
        super(64, 8, STATE_BYTES);
    }

    @Override
    public int digestLength() {
        return 32;
    }

    @Override
    void initState() {
        int[] h = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        };
        for (int i = 0; i < 8; i++) {
            state.set(BE_INT, H_OFFSET + i * 4L, h[i]);
        }
    }

    @Override
    void compress(MemorySegment data, long offset) {
        for (int i = 0; i < 16; i++) {
            state.set(BE_INT, W_OFFSET + i * 4L, data.get(BE_INT, offset + i * 4L));
        }
        for (int i = 16; i < 64; i++) {
            int w15 = state.get(BE_INT, W_OFFSET + (i - 15) * 4L);
            int w2 = state.get(BE_INT, W_OFFSET + (i - 2) * 4L);
            int s0 = Integer.rotateRight(w15, 7) ^ Integer.rotateRight(w15, 18) ^ (w15 >>> 3);
            int s1 = Integer.rotateRight(w2, 17) ^ Integer.rotateRight(w2, 19) ^ (w2 >>> 10);
            int w = state.get(BE_INT, W_OFFSET + (i - 16) * 4L) + s0
                    + state.get(BE_INT, W_OFFSET + (i - 7) * 4L) + s1;
            state.set(BE_INT, W_OFFSET + i * 4L, w);
        }

        int a = state.get(BE_INT, H_OFFSET);
        int b = state.get(BE_INT, H_OFFSET + 4);
        int c = state.get(BE_INT, H_OFFSET + 8);
        int d = state.get(BE_INT, H_OFFSET + 12);
        int e = state.get(BE_INT, H_OFFSET + 16);
        int f = state.get(BE_INT, H_OFFSET + 20);
        int g = state.get(BE_INT, H_OFFSET + 24);
        int h = state.get(BE_INT, H_OFFSET + 28);

        for (int i = 0; i < 64; i++) {
            int s1 = Integer.rotateRight(e, 6) ^ Integer.rotateRight(e, 11) ^ Integer.rotateRight(e, 25);
            int ch = (e & f) ^ (~e & g);
            int temp1 = h + s1 + ch + K[i] + state.get(BE_INT, W_OFFSET + i * 4L);
            int s0 = Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13) ^ Integer.rotateRight(a, 22);
            int maj = (a & b) ^ (a & c) ^ (b & c);
            int temp2 = s0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        add(H_OFFSET, a);
        add(H_OFFSET + 4, b);
        add(H_OFFSET + 8, c);
        add(H_OFFSET + 12, d);
        add(H_OFFSET + 16, e);
        add(H_OFFSET + 20, f);
        add(H_OFFSET + 24, g);
        add(H_OFFSET + 28, h);
    }

    private void add(long offset, int value) {
        state.set(BE_INT, offset, state.get(BE_INT, offset) + value);
    }

    @Override
    void writeResult(MemorySegment out, long offset) {
        MemorySegment.copy(state, H_OFFSET, out, offset, 32);
    }
}
