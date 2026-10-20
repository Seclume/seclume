package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;
import java.util.Random;
import java.util.function.IntConsumer;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Whether the running time of the code that handles secrets depends on them -
 * measured, the way dudect does it ("Dude, is my code constant time?",
 * Reparaz, Balasch, Verbauwhede, 2017).
 *
 * <p>Two classes of input, interleaved at random so that whatever else the
 * machine does falls on both alike; each sample is the time of a batch of
 * calls; the slowest samples are cropped, because what interrupts a
 * measurement is noise and not the code; and Welch's t-test asks whether the
 * two classes differ. |t| above {@value #LEAK} is dudect's threshold for a
 * leak.
 *
 * <p>The negative control comes first in importance: a comparison that
 * returns at the first differing byte has to be found, or a quiet result
 * means only that the measurement cannot see.
 *
 * <p>A JVM is a noisy place to time anything - JIT, GC, safepoints - so this
 * runs when asked ({@code -Dseclume.constantTime=true}, as the nightly fuzz
 * job does) and not in every build. A finding is reported with its t value.
 */
@Timeout(600)
class ConstantTimeLeakageTest {

    /** dudect's threshold: beyond this the two classes are told apart. */
    private static final double LEAK = 4.5;
    private static final int SAMPLES = Integer.getInteger("seclume.constantTime.samples", 200_000);

    @BeforeAll
    static void onlyWhenAsked() {
        Assumptions.assumeTrue(Boolean.getBoolean("seclume.constantTime"),
                "timing measurements run with -Dseclume.constantTime=true");
    }

    // ---- the control -------------------------------------------------------

    /** A comparison that returns at the first difference - what must be found. */
    private static boolean earlyExit(MemorySegment a, MemorySegment b, long length) {
        for (long i = 0; i < length; i++) {
            if (a.get(ValueLayout.JAVA_BYTE, i) != b.get(ValueLayout.JAVA_BYTE, i)) {
                return false;
            }
        }
        return true;
    }

    @Test
    void theNegativeControlLeaks() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment a = random(arena, 64, 1);
            MemorySegment b = arena.allocate(64);
            double t = measure(16, klass -> differAt(a, b, klass == 0 ? 0 : 63, 0, 63),
                    klass -> sink ^= earlyExit(a, b, 64) ? 1 : 0);
            assertTrue(Math.abs(t) > LEAK, "an early exit was not seen (t = " + t
                    + ") - the measurement cannot tell a leak from none");
        }
    }

    // ---- what is measured --------------------------------------------------

    /** The comparison behind the SCRAM server proof and TLS Finished. */
    @Test
    void comparingDoesNotDependOnWhereTheBytesDiffer() {
        try (Arena arena = Arena.ofConfined()) {
            // Both unequal, so the result is the same; only where they differ
            // is not - which is exactly what an early exit gives away.
            MemorySegment a = random(arena, 64, 2);
            MemorySegment b = arena.allocate(64);
            double t = measure(16, klass -> differAt(a, b, klass == 0 ? 0 : 63, 0, 63),
                    klass -> sink ^= ConstantTime.equals(a, 0, b, 0, 64) ? 1 : 0);
            assertTrue(Math.abs(t) < LEAK, "ConstantTime.equals leaks (t = " + t + ")");
        }
    }

    /**
     * The Java AES-GCM refuses a forged tag in the same time wherever the
     * forgery differs - first byte or last.
     */
    @Test
    void aForgedTagIsRefusedInTheSameTimeWhereverItDiffers() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = random(arena, 16, 3);
            MemorySegment nonce = random(arena, 12, 4);
            MemorySegment plain = random(arena, 64, 5);
            MemorySegment sealed = arena.allocate(64 + 16);
            MemorySegment out = arena.allocate(64);
            try (AesKey aes = new AesKey(key)) {
                AesGcm.encrypt(aes, nonce, 0, MemorySegment.NULL, 0, 0, plain, 0, 64, sealed, 0);
                MemorySegment forged = arena.allocate(64 + 16);
                double t = measure(2, klass -> differAt(sealed, forged, klass == 0 ? 64 : 79, 64, 79),
                        klass -> sink ^= AesGcm.decrypt(aes, nonce, 0, MemorySegment.NULL, 0, 0,
                                forged, 0, 64, out, 0) ? 1 : 0);
                assertTrue(Math.abs(t) < LEAK, "the GCM tag check leaks (t = " + t + ")");
            }
        }
    }

    /** One AES block in the Java fallback: a fixed plaintext against random ones. */
    @Test
    void anAesBlockTakesTheSameTimeWhateverItHolds() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = random(arena, 32, 6);
            MemorySegment fixed = arena.allocate(16);
            // The random inputs made beforehand, not while the clock runs:
            // making them in the measured time was what the first version
            // of this test measured (t = -220, all of it the generator).
            MemorySegment randoms = random(arena, 16 * 4096, 7);
            // And both classes read them from the same memory: the fixed block
            // and a random one side by side in one cache line, the pair moving
            // on every sample whichever class is drawn. With the fixed block in
            // a buffer of its own, only the random class streamed 64 KiB through
            // the cache - and the nightly run saw t = -8, the fixed class 2 ns
            // faster in 4.7 us, which is what that layout predicts.
            MemorySegment pairs = arena.allocate(32L * 4096, 64);
            for (int i = 0; i < 4096; i++) {
                MemorySegment.copy(fixed, 0, pairs, 32L * i, 16);
                MemorySegment.copy(randoms, 16L * i, pairs, 32L * i + 16, 16);
            }
            MemorySegment state = arena.allocate(16);
            int[] next = {0};
            try (AesKey aes = new AesKey(key)) {
                // One block per sample: the next would encrypt the ciphertext.
                double t = measure(1, klass -> MemorySegment.copy(pairs,
                                32L * (next[0]++ & 4095) + 16L * klass, state, 0, 16),
                        klass -> Aes.encryptBlock(aes, state));
                assertTrue(Math.abs(t) < LEAK, "the Java AES leaks (t = " + t + ")");
            }
        }
    }

    // ---- dudect ------------------------------------------------------------

    /** Keeps the JIT from removing what is measured. */
    private static volatile int sink;

    /**
     * Welch's t between the two classes: {@code batch} calls of
     * {@code operation} per sample, the class of each sample drawn at random,
     * the slowest tenth of all samples cropped.
     */
    private static double measure(int batch, IntConsumer prepare, IntConsumer operation) {
        Random choice = new Random(42);
        for (int i = 0; i < 20_000; i++) {            // warm the JIT on both classes
            prepare.accept(i & 1);
            operation.accept(i & 1);
        }
        long[] times = new long[SAMPLES];
        byte[] classes = new byte[SAMPLES];
        for (int s = 0; s < SAMPLES; s++) {
            int klass = choice.nextInt(2);
            // The input made outside the clock, into the same memory for both
            // classes: two buffers at two addresses differ in cache and
            // alignment, and at 200 000 samples that alone is significant.
            prepare.accept(klass);
            long start = System.nanoTime();
            for (int i = 0; i < batch; i++) {
                operation.accept(klass);
            }
            times[s] = System.nanoTime() - start;
            classes[s] = (byte) klass;
        }
        long[] sorted = times.clone();
        Arrays.sort(sorted);
        long crop = sorted[(int) (SAMPLES * 0.9)];
        double[] n = new double[2];
        double[] mean = new double[2];
        double[] m2 = new double[2];
        for (int s = 0; s < SAMPLES; s++) {
            if (times[s] > crop) {
                continue;
            }
            int k = classes[s];
            n[k]++;
            double delta = times[s] - mean[k];
            mean[k] += delta / n[k];
            m2[k] += delta * (times[s] - mean[k]);
        }
        double variance0 = m2[0] / (n[0] - 1);
        double variance1 = m2[1] / (n[1] - 1);
        double t = (mean[0] - mean[1]) / Math.sqrt(variance0 / n[0] + variance1 / n[1]);
        System.out.printf("t = %.2f (means %.1f / %.1f ns per batch, %d / %d samples)%n",
                t, mean[0], mean[1], (long) n[0], (long) n[1]);
        return t;
    }

    private static MemorySegment random(Arena arena, int length, long seed) {
        byte[] bytes = new byte[length];
        new Random(seed).nextBytes(bytes);
        return arena.allocateFrom(ValueLayout.JAVA_BYTE, bytes);
    }

    /**
     * {@code into} becomes {@code from} with the byte at {@code flip} - one of
     * {@code low} and {@code high} - changed. Both are written in both classes,
     * in the same order: a store to one place just before the clock starts is
     * itself measurable (a t of 8, a tenth of a nanosecond per call, from
     * which cache line the last store went to).
     */
    private static void differAt(MemorySegment from, MemorySegment into, long flip, long low,
                                 long high) {
        MemorySegment.copy(from, 0, into, 0, into.byteSize());
        byte lowValue = from.get(ValueLayout.JAVA_BYTE, low);
        byte highValue = from.get(ValueLayout.JAVA_BYTE, high);
        into.set(ValueLayout.JAVA_BYTE, low, flip == low ? (byte) ~lowValue : lowValue);
        into.set(ValueLayout.JAVA_BYTE, high, flip == high ? (byte) ~highValue : highValue);
    }

    private static MemorySegment copy(Arena arena, MemorySegment from) {
        MemorySegment to = arena.allocate(from.byteSize());
        MemorySegment.copy(from, 0, to, 0, from.byteSize());
        return to;
    }
}
