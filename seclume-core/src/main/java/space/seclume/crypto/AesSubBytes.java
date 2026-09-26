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
 * then an affine map - evaluated <b>bitsliced</b>: the 16 bytes of a block are
 * turned into eight 16-bit planes (plane {@code i} holds bit {@code i} of
 * every byte), and each step works on all sixteen at once with AND and XOR.
 * The inverse is {@code x^254} (which also maps 0 to 0, as AES wants), six
 * multiplications and seven squarings by an addition chain. The inverse S-box
 * is the inverse affine map followed by the same inversion.
 *
 * <p>Checked against the generated table for all 256 inputs
 * ({@code AesSubBytesTest}); the table itself stays, for that test only.
 */
final class AesSubBytes {

    /** The eight bits of 0x63, the forward affine constant. */
    private static final int FORWARD_CONSTANT = 0x63;
    /** The eight bits of 0x05, the inverse affine constant. */
    private static final int INVERSE_CONSTANT = 0x05;

    private AesSubBytes() {
    }

    /** SubBytes on a 16-byte state, in place. */
    static void forward(MemorySegment state) {
        int[] planes = new int[8]; // seclume-allow: bit planes of the state, zeroed before return
        try {
            load(state, 16, planes);
            invert(planes);
            affine(planes, 0xffff);
            store(planes, state, 16);
        } finally {
            java.util.Arrays.fill(planes, 0);
        }
    }

    /** InvSubBytes on a 16-byte state, in place. */
    static void inverse(MemorySegment state) {
        int[] planes = new int[8]; // seclume-allow: bit planes of the state, zeroed before return
        try {
            load(state, 16, planes);
            inverseAffine(planes, 0xffff);
            invert(planes);
            store(planes, state, 16);
        } finally {
            java.util.Arrays.fill(planes, 0);
        }
    }

    /** SubWord of the key schedule: the S-box on each byte of a word. */
    static int word(int word) {
        int[] planes = new int[8]; // seclume-allow: bit planes of a key word, zeroed before return
        try {
            for (int lane = 0; lane < 4; lane++) {
                int value = word >>> (24 - 8 * lane);
                for (int bit = 0; bit < 8; bit++) {
                    planes[bit] |= ((value >>> bit) & 1) << lane;
                }
            }
            invert(planes);
            affine(planes, 0xf);
            int result = 0;
            for (int lane = 0; lane < 4; lane++) {
                int value = 0;
                for (int bit = 0; bit < 8; bit++) {
                    value |= ((planes[bit] >>> lane) & 1) << bit;
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
        int[] planes = new int[8]; // seclume-allow: a test helper's single byte
        for (int bit = 0; bit < 8; bit++) {
            planes[bit] = (value >>> bit) & 1;
        }
        inverseAffine(planes, 1);
        invert(planes);
        int result = 0;
        for (int bit = 0; bit < 8; bit++) {
            result |= (planes[bit] & 1) << bit;
        }
        return result;
    }

    private static void load(MemorySegment state, int lanes, int[] planes) {
        for (int lane = 0; lane < lanes; lane++) {
            int value = state.get(ValueLayout.JAVA_BYTE, lane) & 0xff;
            for (int bit = 0; bit < 8; bit++) {
                planes[bit] |= ((value >>> bit) & 1) << lane;
            }
        }
    }

    private static void store(int[] planes, MemorySegment state, int lanes) {
        for (int lane = 0; lane < lanes; lane++) {
            int value = 0;
            for (int bit = 0; bit < 8; bit++) {
                value |= ((planes[bit] >>> lane) & 1) << bit;
            }
            state.set(ValueLayout.JAVA_BYTE, lane, (byte) value);
        }
    }

    /**
     * {@code x^254} in place: {@code x^(2^k - 1)} for k = 2..7 by
     * {@code t = t^2 * x}, then one more squaring.
     */
    private static void invert(int[] x) {
        int[] t = x.clone(); // seclume-allow: bit planes, zeroed below
        int[] scratch = new int[8]; // seclume-allow: bit planes, zeroed below
        try {
            for (int step = 0; step < 6; step++) {
                multiply(t, t, scratch);
                multiply(scratch, x, t);
            }
            multiply(t, t, x);
        } finally {
            java.util.Arrays.fill(t, 0);
            java.util.Arrays.fill(scratch, 0);
        }
    }

    /**
     * {@code out = a * b} in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, on bit
     * planes: a schoolbook product of AND and XOR, then the reduction, which
     * folds each coefficient from x^14 down to x^8 onto x^4 + x^3 + x + 1.
     * {@code out} may be neither {@code a} nor {@code b}.
     */
    private static void multiply(int[] a, int[] b, int[] out) {
        int[] c = new int[15]; // seclume-allow: bit planes, zeroed below
        try {
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
        } finally {
            java.util.Arrays.fill(c, 0);
        }
    }

    /** b_i ^ b_(i+4) ^ b_(i+5) ^ b_(i+6) ^ b_(i+7) ^ c_i, on all lanes in {@code mask}. */
    private static void affine(int[] p, int mask) {
        int[] out = new int[8]; // seclume-allow: bit planes, zeroed below
        try {
            for (int i = 0; i < 8; i++) {
                out[i] = p[i] ^ p[(i + 4) & 7] ^ p[(i + 5) & 7] ^ p[(i + 6) & 7] ^ p[(i + 7) & 7]
                        ^ (-((FORWARD_CONSTANT >>> i) & 1) & mask);
            }
            System.arraycopy(out, 0, p, 0, 8);
        } finally {
            java.util.Arrays.fill(out, 0);
        }
    }

    /** b_(i+2) ^ b_(i+5) ^ b_(i+7) ^ d_i - the inverse of {@link #affine}. */
    private static void inverseAffine(int[] p, int mask) {
        int[] out = new int[8]; // seclume-allow: bit planes, zeroed below
        try {
            for (int i = 0; i < 8; i++) {
                out[i] = p[(i + 2) & 7] ^ p[(i + 5) & 7] ^ p[(i + 7) & 7]
                        ^ (-((INVERSE_CONSTANT >>> i) & 1) & mask);
            }
            System.arraycopy(out, 0, p, 0, 8);
        } finally {
            java.util.Arrays.fill(out, 0);
        }
    }
}
