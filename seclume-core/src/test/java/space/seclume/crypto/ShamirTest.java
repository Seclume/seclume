package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.SplittableRandom;

import org.junit.jupiter.api.Test;

/**
 * Shamir's secret sharing over GF(2^8): the field, a known answer from an
 * independent implementation, every combination of a split, and that fewer
 * shares than the threshold say nothing.
 */
class ShamirTest {

    /** Multiplication as the textbook does it, with branches - the reference. */
    private static int slowMultiply(int a, int b) {
        int product = 0;
        while (b != 0) {
            if ((b & 1) != 0) {
                product ^= a;
            }
            a <<= 1;
            if ((a & 0x100) != 0) {
                a ^= 0x11b;
            }
            b >>= 1;
        }
        return product;
    }

    @Test
    void theFieldIsAes() {
        // FIPS 197, section 4.2: {57} x {83} = {c1}, {57} x {13} = {fe}.
        assertEquals(0xc1, Shamir.multiply(0x57, 0x83));
        assertEquals(0xfe, Shamir.multiply(0x57, 0x13));
        for (int a = 0; a < 256; a++) {
            for (int b = 0; b < 256; b++) {
                assertEquals(slowMultiply(a, b), Shamir.multiply(a, b), a + " x " + b);
            }
        }
    }

    @Test
    void everyNonZeroElementHasItsInverse() {
        for (int a = 1; a < 256; a++) {
            int inverse = Shamir.inverse(a);
            assertEquals(1, Shamir.multiply(a, inverse), "inverse of " + a);
        }
        assertEquals(0, Shamir.inverse(0));
    }

    @Test
    void aKnownAnswerFromAnIndependentImplementation() {
        // Python, written apart from this class: secret 00..1f, threshold 3, the
        // coefficients (7i + 3) mod 256; share 1 is the sum of the three rows.
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = arena.allocate(32);
            for (int i = 0; i < 32; i++) {
                secret.set(ValueLayout.JAVA_BYTE, i, (byte) i);
            }
            MemorySegment coefficients = arena.allocate(64);
            for (int i = 0; i < 64; i++) {
                coefficients.set(ValueLayout.JAVA_BYTE, i, (byte) (i * 7 + 3));
            }
            MemorySegment[] out = new MemorySegment[5];
            for (int i = 0; i < 5; i++) {
                out[i] = arena.allocate(32);
            }
            Shamir.split(secret, 0, 32, 3, 5, out, 0, coefficients);
            assertEquals("e0e1e2e3e425262728696a6b6c6d2e2f3031f2f3f4f5f63738393a7b7c7d7e7f",
                    HexFormat.of().formatHex(out[0].toArray(ValueLayout.JAVA_BYTE)));
            MemorySegment back = arena.allocate(32);
            Shamir.combine(new int[] {5, 2, 4}, new MemorySegment[] {out[4], out[1], out[3]},
                    0, 32, back, 0);
            assertArrayEquals(secret.toArray(ValueLayout.JAVA_BYTE), back.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @Test
    void everyChoiceOfThresholdSharesGivesTheSecretBack() {
        SplittableRandom random = new SplittableRandom(31);
        for (int threshold = 2; threshold <= 5; threshold++) {
            for (int shares = threshold; shares <= 6; shares++) {
                try (Arena arena = Arena.ofConfined()) {
                    int length = 1 + random.nextInt(40);
                    MemorySegment secret = arena.allocate(length);
                    for (int i = 0; i < length; i++) {
                        secret.set(ValueLayout.JAVA_BYTE, i, (byte) random.nextInt(256));
                    }
                    MemorySegment[] out = new MemorySegment[shares];
                    for (int i = 0; i < shares; i++) {
                        out[i] = arena.allocate(length);
                    }
                    Shamir.split(secret, 0, length, threshold, shares, out, 0);
                    for (List<Integer> choice : choose(shares, threshold)) {
                        int[] xs = new int[threshold];
                        MemorySegment[] ys = new MemorySegment[threshold];
                        for (int i = 0; i < threshold; i++) {
                            xs[i] = choice.get(i) + 1;
                            ys[i] = out[choice.get(i)];
                        }
                        MemorySegment back = arena.allocate(length);
                        Shamir.combine(xs, ys, 0, length, back, 0);
                        assertArrayEquals(secret.toArray(ValueLayout.JAVA_BYTE),
                                back.toArray(ValueLayout.JAVA_BYTE),
                                threshold + " of " + shares + ", shares " + choice);
                    }
                }
            }
        }
    }

    @Test
    void moreSharesThanTheThresholdAlsoWork() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = arena.allocate(16);
            secret.fill((byte) 0x5a);
            MemorySegment[] out = new MemorySegment[5];
            for (int i = 0; i < 5; i++) {
                out[i] = arena.allocate(16);
            }
            Shamir.split(secret, 0, 16, 3, 5, out, 0);
            MemorySegment back = arena.allocate(16);
            Shamir.combine(new int[] {1, 2, 3, 4, 5}, out, 0, 16, back, 0);
            assertArrayEquals(secret.toArray(ValueLayout.JAVA_BYTE), back.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @Test
    void fewerSharesThanTheThresholdGiveSomethingElse() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = arena.allocate(32);
            secret.fill((byte) 0x11);
            MemorySegment[] out = new MemorySegment[5];
            for (int i = 0; i < 5; i++) {
                out[i] = arena.allocate(32);
            }
            Shamir.split(secret, 0, 32, 3, 5, out, 0);
            MemorySegment back = arena.allocate(32);
            Shamir.combine(new int[] {1, 2}, new MemorySegment[] {out[0], out[1]}, 0, 32, back, 0);
            assertFalse(java.util.Arrays.equals(secret.toArray(ValueLayout.JAVA_BYTE),
                    back.toArray(ValueLayout.JAVA_BYTE)));
        }
    }

    /**
     * Perfect secrecy, exhaustively for one byte at threshold 2: whatever the
     * secret, every value of a single share is reached by exactly one
     * coefficient - so the share is uniform and independent of the secret.
     */
    @Test
    void oneShareBelowTheThresholdSaysNothing() {
        for (int x = 1; x <= 255; x += 37) {
            for (int s = 0; s < 256; s++) {
                int[] seen = new int[256];
                for (int a = 0; a < 256; a++) {
                    seen[Shamir.multiply(a, x) ^ s]++;
                }
                for (int y = 0; y < 256; y++) {
                    assertEquals(1, seen[y], "x " + x + ", secret " + s + ", share " + y);
                }
            }
        }
    }

    /**
     * The same at threshold 3: for any two shares, every pair of values they
     * can take comes from exactly 256 polynomials, whatever the secret.
     */
    @Test
    void twoSharesBelowAThresholdOfThreeSayNothing() {
        int x1 = 3;
        int x2 = 200;
        for (int s : new int[] {0, 1, 0x80, 0xff}) {
            int[] seen = new int[65536];
            for (int a1 = 0; a1 < 256; a1++) {
                for (int a2 = 0; a2 < 256; a2++) {
                    int y1 = s ^ Shamir.multiply(a1, x1) ^ Shamir.multiply(a2, Shamir.multiply(x1, x1));
                    int y2 = s ^ Shamir.multiply(a1, x2) ^ Shamir.multiply(a2, Shamir.multiply(x2, x2));
                    seen[y1 << 8 | y2]++;
                }
            }
            for (int pair = 0; pair < 65536; pair++) {
                assertEquals(1, seen[pair], "secret " + s);
            }
        }
    }

    @Test
    void theCoefficientsAreFreshEachTime() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = arena.allocate(32);
            MemorySegment[] first = {arena.allocate(32), arena.allocate(32)};
            MemorySegment[] second = {arena.allocate(32), arena.allocate(32)};
            Shamir.split(secret, 0, 32, 2, 2, first, 0);
            Shamir.split(secret, 0, 32, 2, 2, second, 0);
            assertFalse(java.util.Arrays.equals(first[0].toArray(ValueLayout.JAVA_BYTE),
                    second[0].toArray(ValueLayout.JAVA_BYTE)));
        }
    }

    @Test
    void nonsenseIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = arena.allocate(4);
            MemorySegment[] out = new MemorySegment[256];
            for (int i = 0; i < out.length; i++) {
                out[i] = arena.allocate(4);
            }
            assertThrows(IllegalArgumentException.class, () -> Shamir.split(secret, 0, 4, 1, 3, out, 0));
            assertThrows(IllegalArgumentException.class, () -> Shamir.split(secret, 0, 4, 4, 3, out, 0));
            assertThrows(IllegalArgumentException.class, () -> Shamir.split(secret, 0, 4, 2, 256, out, 0));
            assertThrows(IllegalArgumentException.class, () -> Shamir.split(secret, 0, 4, 2, 3,
                    new MemorySegment[2], 0));
            MemorySegment back = arena.allocate(4);
            assertThrows(IllegalArgumentException.class, () -> Shamir.combine(new int[] {1, 1},
                    new MemorySegment[] {out[0], out[1]}, 0, 4, back, 0));
            assertThrows(IllegalArgumentException.class, () -> Shamir.combine(new int[] {0, 1},
                    new MemorySegment[] {out[0], out[1]}, 0, 4, back, 0));
            assertThrows(IllegalArgumentException.class, () -> Shamir.combine(new int[] {1},
                    new MemorySegment[] {out[0]}, 0, 4, back, 0));
            assertTrue(true);
        }
    }

    private static List<List<Integer>> choose(int n, int k) {
        List<List<Integer>> all = new ArrayList<>();
        choose(0, n, k, new ArrayList<>(), all);
        return all;
    }

    private static void choose(int from, int n, int k, List<Integer> current, List<List<Integer>> all) {
        if (current.size() == k) {
            all.add(List.copyOf(current));
            return;
        }
        for (int i = from; i < n; i++) {
            current.add(i);
            choose(i + 1, n, k, current, all);
            current.remove(current.size() - 1);
        }
    }
}
