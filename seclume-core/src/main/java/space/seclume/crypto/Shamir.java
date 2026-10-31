package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.internal.Entropy;

/**
 * Shamir's secret sharing over GF(2^8), byte by byte, in native memory.
 *
 * <p>A secret is split into {@code n} shares so that any {@code k} of them give
 * it back and any {@code k - 1} say nothing about it: for every byte a random
 * polynomial of degree {@code k - 1} is drawn whose constant term is that byte,
 * and share {@code x} holds its value at {@code x}. With {@code k} points the
 * polynomial is fixed and Lagrange interpolation at zero returns the byte; with
 * fewer, every value of the byte is equally consistent with what is known.
 *
 * <p>The field is the one AES uses, {@code x^8 + x^4 + x^3 + x + 1}. Its
 * arithmetic here has no tables and no branches on data: a multiplication is
 * eight conditional XORs done as masks, an inverse is {@code a^254} by a fixed
 * chain of squarings - so the time a combination takes does not depend on the
 * shares. The coefficients are drawn from the operating system's random source
 * into native memory and zeroed before this returns.
 *
 * <p>This class does the arithmetic only; what a share looks like on disk, how
 * shares that belong together are recognised and how a wrong combination is
 * noticed is {@link space.seclume.secret.ShamirShares}.
 */
public final class Shamir {

    /** At most this many shares: their x-coordinates are the non-zero bytes. */
    public static final int MAX_SHARES = 255;

    private Shamir() {
    }

    /** The product of two field elements, without tables or data-dependent branches. */
    static int multiply(int a, int b) {
        int product = 0;
        for (int i = 0; i < 8; i++) {
            product ^= -(b & 1) & a;
            int carry = -((a >>> 7) & 1);
            a = ((a << 1) ^ (carry & 0x1b)) & 0xff;
            b >>>= 1;
        }
        return product & 0xff;
    }

    /** The inverse, {@code a^254}; the inverse of 0 comes out as 0 and is never asked for. */
    static int inverse(int a) {
        int result = 1;
        int power = a;
        // 254 = 0b11111110: square every time, multiply in for bits 1 to 7.
        for (int bit = 1; bit < 8; bit++) {
            power = multiply(power, power);
            result = multiply(result, power);
        }
        return result;
    }

    /**
     * Splits {@code length} bytes of {@code secret} into {@code shares} shares,
     * any {@code threshold} of which recover it. Share {@code i} (its
     * x-coordinate is {@code i + 1}) is written to {@code out[i]} at offset
     * {@code outOffset}, {@code length} bytes.
     */
    public static void split(MemorySegment secret, long offset, int length, int threshold,
            int shares, MemorySegment[] out, long outOffset) {
        check(threshold, shares, out.length);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment coefficients = arena.allocate(Math.max(1L, (long) (threshold - 1) * length));
            try {
                Entropy.fill(coefficients);
                split(secret, offset, length, threshold, shares, out, outOffset, coefficients);
            } finally {
                coefficients.fill((byte) 0);
            }
        }
    }

    /**
     * The split with the coefficients given: byte {@code j}'s polynomial is
     * {@code s_j + c[0][j] x + c[1][j] x^2 + ...}, {@code c[m]} at
     * {@code m * length}. For the known-answer tests; everything else draws them.
     */
    static void split(MemorySegment secret, long offset, int length, int threshold, int shares,
            MemorySegment[] out, long outOffset, MemorySegment coefficients) {
        check(threshold, shares, out.length);
        for (int i = 0; i < shares; i++) {
            int x = i + 1;
            for (int j = 0; j < length; j++) {
                int y = 0;
                for (int m = threshold - 2; m >= 0; m--) {
                    y = multiply(y, x) ^ (coefficients.get(ValueLayout.JAVA_BYTE,
                            (long) m * length + j) & 0xff);
                }
                y = multiply(y, x) ^ (secret.get(ValueLayout.JAVA_BYTE, offset + j) & 0xff);
                out[i].set(ValueLayout.JAVA_BYTE, outOffset + j, (byte) y);
            }
        }
    }

    /**
     * Interpolates at zero: {@code xs.length} shares, share {@code i} at
     * x-coordinate {@code xs[i]} with its bytes in {@code ys[i]} at
     * {@code yOffset}, give {@code length} bytes into {@code target} at
     * {@code targetOffset}. The x-coordinates must be distinct and non-zero.
     * Fewer shares than the threshold they were made with give a wrong value,
     * not an error - noticing that is the caller's business.
     */
    public static void combine(int[] xs, MemorySegment[] ys, long yOffset, int length,
            MemorySegment target, long targetOffset) {
        if (xs.length != ys.length || xs.length < 2) {
            throw new IllegalArgumentException("at least two shares, one x for each");
        }
        int[] weights = new int[xs.length];
        for (int i = 0; i < xs.length; i++) {
            if (xs[i] < 1 || xs[i] > MAX_SHARES) {
                throw new IllegalArgumentException("a share's x is 1 to 255, not " + xs[i]);
            }
            int weight = 1;
            for (int j = 0; j < xs.length; j++) {
                if (j == i) {
                    continue;
                }
                if (xs[j] == xs[i]) {
                    throw new IllegalArgumentException("two shares with the same x, " + xs[i]);
                }
                // l_i(0) = prod over j != i of x_j / (x_j - x_i); minus is XOR here.
                weight = multiply(weight, multiply(xs[j], inverse(xs[j] ^ xs[i])));
            }
            weights[i] = weight;
        }
        for (int b = 0; b < length; b++) {
            int value = 0;
            for (int i = 0; i < xs.length; i++) {
                value ^= multiply(ys[i].get(ValueLayout.JAVA_BYTE, yOffset + b) & 0xff, weights[i]);
            }
            target.set(ValueLayout.JAVA_BYTE, targetOffset + b, (byte) value);
        }
    }

    private static void check(int threshold, int shares, int outputs) {
        if (threshold < 2) {
            throw new IllegalArgumentException("a threshold of " + threshold
                    + " is no sharing at all - at least 2");
        }
        if (shares < threshold || shares > MAX_SHARES) {
            throw new IllegalArgumentException("between the threshold (" + threshold
                    + ") and " + MAX_SHARES + " shares, not " + shares);
        }
        if (outputs < shares) {
            throw new IllegalArgumentException(shares + " shares need as many outputs, not "
                    + outputs);
        }
    }
}
