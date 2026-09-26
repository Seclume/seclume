package space.seclume.crypto;

/**
 * The S-box, inverse S-box and Rcon of AES - computed rather than typed out.
 *
 * <p>The tables appear in FIPS-197 as 512 hex numbers. Typed out they are a
 * source of error that no test vector reliably catches, because a single wrong
 * entry only affects certain inputs. Generated from the definition -
 * multiplicative inverse in GF(2^8) plus the affine map - they cannot be wrong
 * in the first place.
 *
 * <p>Public constants, not a secret: they may therefore live on the heap as
 * {@code byte[]}.
 */
final class AesTables {

    static final byte[] SBOX = new byte[256];
    static final byte[] INV_SBOX = new byte[256];
    static final int[] RCON = new int[15];

    static {
        int p = 1;
        int q = 1;
        do {
            // p = p * 3 in GF(2^8)
            p = (p ^ (p << 1) ^ (((p & 0x80) != 0) ? 0x11b : 0)) & 0xff;
            // q = q / 3 in GF(2^8)
            q ^= q << 1;
            q ^= q << 2;
            q ^= q << 4;
            q &= 0xff;
            if ((q & 0x80) != 0) {
                q ^= 0x09;
            }
            int transformed = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
            SBOX[p] = (byte) ((transformed ^ 0x63) & 0xff);
        } while (p != 1);
        SBOX[0] = 0x63;

        for (int i = 0; i < 256; i++) {
            INV_SBOX[SBOX[i] & 0xff] = (byte) i;
        }

        int rcon = 1;
        for (int i = 1; i < RCON.length; i++) {
            RCON[i] = rcon << 24;
            rcon = xtime(rcon);
        }
    }

    private AesTables() {
    }

    private static int rotl8(int value, int shift) {
        return ((value << shift) | (value >>> (8 - shift))) & 0xff;
    }

    /** Multiplication by x in GF(2^8) using the AES polynomial. */
    static int xtime(int value) {
        // No branch on the top bit: MixColumns feeds secret state through
        // here, and a branch is a timing difference.
        int shifted = value << 1;
        return (shifted ^ (0x11b & -((shifted >>> 8) & 1))) & 0xff;
    }

    /** Multiplication of two values in GF(2^8). */
    static int multiply(int a, int b) {
        // Eight rounds whatever the operands, and a mask instead of a branch:
        // either operand may be secret.
        int result = 0;
        int x = a & 0xff;
        for (int bit = 0; bit < 8; bit++) {
            result ^= x & -((b >>> bit) & 1);
            x = xtime(x);
        }
        return result & 0xff;
    }
}
