package space.seclume.bench;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigDecimal;
import java.util.Arrays;

/**
 * What a decimal costs on the way out of the receive buffer.
 *
 * <p>{@code DecodeProbe} settled the integer case: the cost is the number of
 * checked accesses, and reading eight bytes at a time removes it. A
 * {@code double} and a {@code BigDecimal} are the two values that still go
 * through a {@code String} - {@code Double.parseDouble(stringAt(column))} -
 * which is a copy out of native memory and an object per value.
 *
 * <p>Four arms, the same values in all of them:
 *
 * <ul>
 *   <li><b>String + parseDouble</b> - what the drivers do today.</li>
 *   <li><b>exact fast path</b> - the digits as a {@code long} and one
 *       multiplication or division by a power of ten. Correct only where the
 *       mantissa fits in 2^53 and the exponent is one of the powers of ten a
 *       double holds exactly; that is the classic strtod fast path, and
 *       anything outside it has to fall back.</li>
 *   <li><b>String + BigDecimal</b> - what the drivers do today.</li>
 *   <li><b>char[] + BigDecimal</b> - the JDK's own parser, reading a reused
 *       array instead of a fresh String.</li>
 * </ul>
 */
public final class NumberProbe {

    private NumberProbe() {
    }

    private static final int VALUES = 100_000;
    private static final int STRIDE = 16;

    /** Powers of ten a double holds exactly. */
    private static final double[] EXACT = new double[23];

    static {
        double power = 1;
        for (int i = 0; i < EXACT.length; i++) {
            EXACT[i] = power;
            power *= 10;
        }
    }

    public static void main(String[] args) throws Exception {
        int repeats = args.length > 0 ? Integer.parseInt(args[0]) : 100;

        byte[] heap = new byte[VALUES * STRIDE];
        int[] lengths = new int[VALUES];
        for (int i = 0; i < VALUES; i++) {
            // Money, which is what a decimal column usually holds.
            String text = (i % 100_000) + "." + String.format("%02d", i % 100);
            byte[] bytes = text.getBytes(java.nio.charset.StandardCharsets.US_ASCII); // seclume-allow: generated measurement data, no secret in this module
            System.arraycopy(bytes, 0, heap, i * STRIDE, bytes.length);
            lengths[i] = bytes.length;
        }

        try (Arena arena = Arena.ofShared()) {
            MemorySegment data = arena.allocate(heap.length + 8);
            MemorySegment.copy(heap, 0, data, ValueLayout.JAVA_BYTE, 0, heap.length);

            long[][] times = new long[4][repeats];
            double sink = 0;
            for (int i = 0; i < repeats + 30; i++) {
                long a = System.nanoTime();
                sink += doubleViaString(data, lengths);
                long b = System.nanoTime();
                sink += doubleFastPath(data, lengths);
                long c = System.nanoTime();
                sink += decimalViaString(data, lengths);
                long d = System.nanoTime();
                sink += decimalViaChars(data, lengths);
                long e = System.nanoTime();
                if (i >= 30) {
                    times[0][i - 30] = b - a;
                    times[1][i - 30] = c - b;
                    times[2][i - 30] = d - c;
                    times[3][i - 30] = e - d;
                }
            }
            report("double: String + parseDouble", times[0]);
            report("double: exact fast path     ", times[1]);
            report("BigDecimal: String          ", times[2]);
            report("BigDecimal: char[]          ", times[3]);
            System.out.println("(checksum " + sink + ")");
        }
    }

    private static double doubleViaString(MemorySegment data, int[] lengths) {
        double total = 0;
        byte[] scratch = new byte[STRIDE];
        for (int i = 0; i < lengths.length; i++) {
            int length = lengths[i];
            MemorySegment.copy(data, ValueLayout.JAVA_BYTE, (long) i * STRIDE,
                    scratch, 0, length);
            total += Double.parseDouble(new String(scratch, 0, length, // seclume-allow: the arm being measured is exactly this String
                    java.nio.charset.StandardCharsets.US_ASCII));
        }
        return total;
    }

    private static double doubleFastPath(MemorySegment data, int[] lengths) {
        double total = 0;
        for (int i = 0; i < lengths.length; i++) {
            total += exactDouble(data, i * STRIDE, lengths[i]);
        }
        return total;
    }

    /** The digits as a long, then one exact operation - or NaN to say "fall back". */
    private static double exactDouble(MemorySegment data, int offset, int length) {
        long mantissa = 0;
        int digits = 0;
        int fraction = -1;
        boolean negative = false;
        int i = 0;
        if (length > 0 && data.get(ValueLayout.JAVA_BYTE, offset) == '-') {
            negative = true;
            i = 1;
        }
        for (; i < length; i++) {
            int c = data.get(ValueLayout.JAVA_BYTE, offset + i) & 0xff;
            if (c == '.') {
                if (fraction >= 0) {
                    return Double.NaN;
                }
                fraction = 0;
                continue;
            }
            int digit = c - '0';
            if (digit < 0 || digit > 9) {
                return Double.NaN;             // exponent, NaN, Infinity: fall back
            }
            mantissa = mantissa * 10 + digit;
            digits++;
            if (fraction >= 0) {
                fraction++;
            }
            if (digits > 15) {
                return Double.NaN;             // no longer exact in a long
            }
        }
        double value = negative ? -mantissa : mantissa;
        if (fraction <= 0) {
            return value;
        }
        if (fraction >= EXACT.length) {
            return Double.NaN;
        }
        return value / EXACT[fraction];
    }

    private static double decimalViaString(MemorySegment data, int[] lengths) {
        double total = 0;
        byte[] scratch = new byte[STRIDE];
        for (int i = 0; i < lengths.length; i++) {
            int length = lengths[i];
            MemorySegment.copy(data, ValueLayout.JAVA_BYTE, (long) i * STRIDE,
                    scratch, 0, length);
            total += new BigDecimal(new String(scratch, 0, length, // seclume-allow: the arm being measured is exactly this String
                    java.nio.charset.StandardCharsets.US_ASCII)).scale();
        }
        return total;
    }

    private static double decimalViaChars(MemorySegment data, int[] lengths) {
        double total = 0;
        char[] scratch = new char[STRIDE]; // seclume-allow: generated measurement data, no secret in this module
        for (int i = 0; i < lengths.length; i++) {
            int length = lengths[i];
            for (int b = 0; b < length; b++) {
                scratch[b] = (char) (data.get(ValueLayout.JAVA_BYTE,
                        (long) i * STRIDE + b) & 0xff);
            }
            total += new BigDecimal(scratch, 0, length).scale();
        }
        return total;
    }

    private static void report(String what, long[] times) {
        long[] sorted = times.clone();
        Arrays.sort(sorted);
        System.out.printf("  %s  p50 %8.3f ms  best %8.3f ms%n",
                what, sorted[sorted.length / 2] / 1e6, sorted[0] / 1e6);
    }
}
