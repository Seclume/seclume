package space.seclume.crypto;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * AES's S-box, computed in constant time instead of looked up.
 *
 * <p>A table lookup {@code SBOX[secret]} touches a cache line chosen by the
 * secret, and which lines were touched can be measured from another thread on
 * the same core - the classic cache-timing attack on table-driven AES
 * (Bernstein 2005, Osvik-Shamir-Tromer 2006). Every S-box input here is
 * secret: plaintext or state mixed with the key, and in the key schedule the
 * key itself. So nothing here indexes memory or branches on a secret.
 *
 * <p>The S-box is what FIPS-197 defines it to be - the inverse in GF(2^8),
 * then an affine map - evaluated <b>bitsliced</b>: the bytes are turned into
 * eight 64-bit planes (plane {@code i} holds bit {@code i} of every byte), and
 * each step works on all of them at once with AND and XOR. A plane has room
 * for 64 bytes, so the four blocks counter mode encrypts together cost what
 * one block does. The inverse is {@code x^254} (which also maps 0 to 0, as AES
 * wants), four multiplications and seven squarings by the Itoh-Tsujii chain.
 * The inverse S-box is the inverse affine map followed by the same inversion.
 *
 * <p>Checked against the generated table for all 256 inputs
 * ({@code AesSubBytesTest}); the table itself stays, for that test only.
 */
final class AesSubBytes {

    /** The eight bits of 0x63, the forward affine constant. */
    private static final int FORWARD_CONSTANT = 0x63;
    /** The eight bits of 0x05, the inverse affine constant. */
    private static final int INVERSE_CONSTANT = 0x05;

    private static final ValueLayout.OfLong LITTLE_LONG =
            ValueLayout.JAVA_LONG_UNALIGNED.withOrder(java.nio.ByteOrder.LITTLE_ENDIAN);

    /** The most bytes one pass takes: a plane is a {@code long}. */
    static final int MAX_LANES = 64;

    private AesSubBytes() {
    }

    /** SubBytes on a 16-byte state, in place. */
    static void forward(MemorySegment state) {
        forward(state, 16);
    }

    /** SubBytes on the first {@code lanes} bytes - up to 64, four blocks - in place. */
    static void forward(MemorySegment states, int lanes) {
        if (lanes <= 0 || lanes > MAX_LANES || lanes % 8 != 0) {
            throw new IllegalArgumentException("8 to 64 bytes in steps of 8, not " + lanes);
        }
        long[] planes = new long[8]; // seclume-allow: bit planes of the state, zeroed before return
        try {
            load(states, lanes, planes);
            invert(planes);
            affine(planes, mask(lanes));
            store(planes, states, lanes);
        } finally {
            java.util.Arrays.fill(planes, 0);
        }
    }

    /** InvSubBytes on a 16-byte state, in place. */
    static void inverse(MemorySegment state) {
        long[] planes = new long[8]; // seclume-allow: bit planes of the state, zeroed before return
        try {
            load(state, 16, planes);
            inverseAffine(planes, mask(16));
            invert(planes);
            store(planes, state, 16);
        } finally {
            java.util.Arrays.fill(planes, 0);
        }
    }

    /** SubWord of the key schedule: the S-box on each byte of a word. */
    static int word(int word) {
        long[] planes = new long[8]; // seclume-allow: bit planes of a key word, zeroed before return
        try {
            for (int lane = 0; lane < 4; lane++) {
                int value = word >>> (24 - 8 * lane);
                for (int bit = 0; bit < 8; bit++) {
                    planes[bit] |= (long) ((value >>> bit) & 1) << lane;
                }
            }
            invert(planes);
            affine(planes, mask(4));
            int result = 0;
            for (int lane = 0; lane < 4; lane++) {
                int value = 0;
                for (int bit = 0; bit < 8; bit++) {
                    value |= (int) ((planes[bit] >>> lane) & 1) << bit;
                }
                result |= value << (24 - 8 * lane);
            }
            return result;
        } finally {
            java.util.Arrays.fill(planes, 0);
        }
    }

    /** One byte, forward - for the exhaustive test against the table. */
    static int forwardByte(int value) {
        return word(value & 0xff) & 0xff;
    }

    /** One byte, inverse - for the exhaustive test against the table. */
    static int inverseByte(int value) {
        long[] planes = new long[8]; // seclume-allow: a test helper's single byte
        for (int bit = 0; bit < 8; bit++) {
            planes[bit] = (value >>> bit) & 1;
        }
        inverseAffine(planes, 1);
        invert(planes);
        int result = 0;
        for (int bit = 0; bit < 8; bit++) {
            result |= (int) (planes[bit] & 1) << bit;
        }
        return result;
    }

    private static long mask(int lanes) {
        return lanes == 64 ? -1L : (1L << lanes) - 1;
    }

    /**
     * Bytes to bit planes, eight bytes at a time: an 8x8 bit transpose turns
     * "byte i, bit j" into "byte j, bit i", and byte j of that is then eight
     * lanes of plane j. Three masked shifts, no branch and no lookup - and
     * several times faster than moving the 512 bits one by one, which is what
     * this spent most of its time on once the inversion was cheap.
     */
    private static void load(MemorySegment state, int lanes, long[] planes) {
        for (int group = 0; group < lanes; group += 8) {
            long bits = transpose(state.get(LITTLE_LONG, group));
            for (int bit = 0; bit < 8; bit++) {
                planes[bit] |= ((bits >>> (8 * bit)) & 0xff) << group;
            }
        }
    }

    private static void store(long[] planes, MemorySegment state, int lanes) {
        for (int group = 0; group < lanes; group += 8) {
            long bits = 0;
            for (int bit = 0; bit < 8; bit++) {
                bits |= ((planes[bit] >>> group) & 0xff) << (8 * bit);
            }
            state.set(LITTLE_LONG, group, transpose(bits));
        }
    }

    /** Bit 8r + c to bit 8c + r - its own inverse (Hacker's Delight, 7-3). */
    private static long transpose(long x) {
        long t = (x ^ (x >>> 7)) & 0x00AA00AA00AA00AAL;
        x = x ^ t ^ (t << 7);
        t = (x ^ (x >>> 14)) & 0x0000CCCC0000CCCCL;
        x = x ^ t ^ (t << 14);
        t = (x ^ (x >>> 28)) & 0x00000000F0F0F0F0L;
        return x ^ t ^ (t << 28);
    }

    /** {@code x^254} in place - the S-box's inversion, on bit planes. */
    private static void invert(long[] x) {
        // x^3, x^15, x^63, x^127 and one last squaring. A squaring is linear in
        // GF(2^8), so on bit planes it is a handful of XORs; this used to be
        // thirteen full multiplications, and it is what the Java AES spends
        // its time on.
        long[] c = new long[15]; // seclume-allow: bit planes, zeroed below
        long[] s = new long[8]; // seclume-allow: bit planes, zeroed below
        long[] x3 = new long[8]; // seclume-allow: bit planes, zeroed below
        long[] a = new long[8]; // seclume-allow: bit planes, zeroed below
        try {
            square(x, s);
            multiply(s, x, x3, c);           // x^3
            square(x3, s);
            square(s, a);
            multiply(a, x3, a, c);           // x^15
            square(a, s);
            square(s, a);
            multiply(a, x3, a, c);           // x^63
            square(a, s);
            multiply(s, x, a, c);            // x^127
            square(a, x);                    // x^254
        } finally {
            java.util.Arrays.fill(c, 0);
            java.util.Arrays.fill(s, 0);
            java.util.Arrays.fill(x3, 0);
            java.util.Arrays.fill(a, 0);
        }
    }

    /**
     * {@code out = in^2} modulo x^8 + x^4 + x^3 + x + 1; {@code out} must not
     * be {@code in}. Bit k of the square is the XOR of the bits i for which
     * x^(2i) reduces to a polynomial with x^k in it.
     */
    private static void square(long[] in, long[] out) {
        out[0] = in[0] ^ in[4] ^ in[6];
        out[1] = in[4] ^ in[6] ^ in[7];
        out[2] = in[1] ^ in[5];
        out[3] = in[4] ^ in[5] ^ in[6] ^ in[7];
        out[4] = in[2] ^ in[4] ^ in[7];
        out[5] = in[5] ^ in[6];
        out[6] = in[3] ^ in[5];
        out[7] = in[6] ^ in[7];
    }

    /**
     * {@code out = a * b} in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, on bit
     * planes: a schoolbook product of AND and XOR into the scratch {@code c},
     * then the reduction, which folds each coefficient from x^14 down to x^8
     * onto x^4 + x^3 + x + 1. {@code out} may be {@code a} or {@code b}: it is
     * written only at the end.
     */
    private static void multiply(long[] a, long[] b, long[] out, long[] c) {
        java.util.Arrays.fill(c, 0);
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                c[i + j] ^= a[i] & b[j];
            }
        }
        for (int k = 14; k >= 8; k--) {
            c[k - 4] ^= c[k];
            c[k - 5] ^= c[k];
            c[k - 7] ^= c[k];
            c[k - 8] ^= c[k];
        }
        System.arraycopy(c, 0, out, 0, 8);
    }

    /** b_i ^ b_(i+4) ^ b_(i+5) ^ b_(i+6) ^ b_(i+7) ^ c_i, on all lanes in {@code mask}. */
    private static void affine(long[] p, long mask) {
        long[] out = new long[8]; // seclume-allow: bit planes, zeroed below
        try {
            for (int i = 0; i < 8; i++) {
                out[i] = p[i] ^ p[(i + 4) & 7] ^ p[(i + 5) & 7] ^ p[(i + 6) & 7] ^ p[(i + 7) & 7]
                        ^ (-(long) ((FORWARD_CONSTANT >>> i) & 1) & mask);
            }
            System.arraycopy(out, 0, p, 0, 8);
        } finally {
            java.util.Arrays.fill(out, 0);
        }
    }

    /** b_(i+2) ^ b_(i+5) ^ b_(i+7) ^ d_i - the inverse of {@link #affine}. */
    private static void inverseAffine(long[] p, long mask) {
        long[] out = new long[8]; // seclume-allow: bit planes, zeroed below
        try {
            for (int i = 0; i < 8; i++) {
                out[i] = p[(i + 2) & 7] ^ p[(i + 5) & 7] ^ p[(i + 7) & 7]
                        ^ (-(long) ((INVERSE_CONSTANT >>> i) & 1) & mask);
            }
            System.arraycopy(out, 0, p, 0, 8);
        } finally {
            java.util.Arrays.fill(out, 0);
        }
    }
}
