package space.seclume.internal.jdbc;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;

import space.seclume.internal.WireBuffer;

/**
 * An integer out of a run of digits, eight bytes per memory access.
 *
 * <p>PostgreSQL and MySQL send a number in their text protocols as the
 * characters of that number, so every value a result carries has to be parsed.
 * The obvious loop reads one byte, checks it, multiplies and goes on - and on a
 * {@link java.lang.foreign.MemorySegment} that is the expensive shape, because
 * a checked access costs the same for one byte as for eight and the cost is per
 * <b>access</b>. Three hundred thousand values, measured by
 * {@code space.seclume.bench.DecodeProbe}:
 *
 * <pre>
 * byte[], a digit at a time              0.69 ms
 * MemorySegment, a digit at a time       2.42 ms
 * MemorySegment, eight bytes per access  0.73 ms
 * </pre>
 *
 * <p>So the segment is not the problem and the heap is not the answer - the
 * same probe measures a segment over a heap array at 4.12 ms, which is worse
 * than either. The number of accesses is the problem, and this is where that is
 * fixed for every driver that speaks a text protocol.
 *
 * <p>The bounds check is why the wide read sits inside a loop rather than in
 * front of it: near the end of the buffer there may not be eight bytes left to
 * read even though the value itself ends well before that. Those last digits
 * are taken one at a time, which is correct and rare.
 */
public final class TextNumber {

    private TextNumber() {
    }

    /**
     * The decimal integer written at {@code offset}, with an optional leading
     * minus.
     *
     * <p>An empty cell is zero, as the digit-at-a-time loop this replaces also
     * answered. Anything that is not a digit raises
     * {@link NumberFormatException} - the callers turn that into the message
     * and the SQL state their own layer owes, which is why this does not throw
     * {@code SQLException} itself.
     */
    public static long decimal(WireBuffer buffer, int offset, int length) {
        boolean negative = false;
        int i = 0;
        if (length > 0 && buffer.getByte(offset) == '-') {
            negative = true;
            i = 1;
        }
        int capacity = buffer.capacity();
        long value = 0;
        while (i < length) {
            if (offset + i + 8 <= capacity) {
                long eight = buffer.getLongLe(offset + i);
                int take = Math.min(8, length - i);
                for (int b = 0; b < take; b++) {
                    // Little endian: the first byte of the value is the lowest.
                    value = value * 10 + digit((int) ((eight >>> (b * 8)) & 0xff));
                }
                i += take;
            } else {
                value = value * 10 + digit(buffer.getByte(offset + i) & 0xff);
                i++;
            }
        }
        return negative ? -value : value;
    }


    /**
     * Powers of ten a {@code double} holds exactly - 10^0 to 10^22.
     *
     * <p>The bound is not a guess: 10^23 is the first power of ten that is not
     * representable, and dividing by an inexact power would round twice.
     */
    private static final double[] EXACT_POWERS = new double[23];

    static {
        double power = 1;
        for (int i = 0; i < EXACT_POWERS.length; i++) {
            EXACT_POWERS[i] = power;
            power *= 10;
        }
    }

    /** Below 2^53, so the digits of such a number survive in a double unchanged. */
    private static final int EXACT_DIGITS = 15;

    /**
     * The {@code double} written at {@code offset} as text.
     *
     * <p>The plain shapes - digits, an optional minus, an optional decimal
     * point - are computed from the digits directly: the mantissa as a
     * {@code long}, then <b>one</b> division by a power of ten the double holds
     * exactly. That is correctly rounded because it rounds once, which is the
     * same argument every C library's {@code strtod} fast path rests on, and it
     * is why the two bounds above are what they are rather than round numbers.
     *
     * <p>Everything else - an exponent, {@code NaN}, {@code Infinity}, more
     * than fifteen digits, a second decimal point - falls back to
     * {@link Double#parseDouble}, which is the JDK's correctly rounded parser
     * and which needs the {@code String} this exists to avoid. That path
     * allocates exactly what the old code allocated for every value.
     *
     * <p>Measured over a hundred thousand money-shaped values
     * ({@code space.seclume.bench.NumberProbe}): 5.11 ms through a
     * {@code String}, <b>1.00 ms</b> this way.
     */
    public static double decimalDouble(WireBuffer buffer, int offset, int length) {
        long mantissa = 0;
        int digits = 0;
        int fraction = -1;
        boolean negative = false;
        int i = 0;
        if (length > 0 && buffer.getByte(offset) == '-') {
            negative = true;
            i = 1;
        }
        boolean exact = i < length;
        for (; i < length && exact; i++) {
            int character = buffer.getByte(offset + i) & 0xff;
            if (character == '.') {
                exact = fraction < 0;
                fraction = 0;
                continue;
            }
            int digit = character - '0';
            if (digit < 0 || digit > 9 || digits >= EXACT_DIGITS) {
                exact = false;
                break;
            }
            mantissa = mantissa * 10 + digit;
            digits++;
            if (fraction >= 0) {
                fraction++;
            }
        }
        // digits == 0 covers "", "-", "." and ".e3": shapes the fast path would
        // answer with zero and Double.parseDouble refuses. It has to keep
        // refusing them.
        if (!exact || digits == 0 || fraction >= EXACT_POWERS.length) {
            return Double.parseDouble(text(buffer, offset, length).trim());
        }
        // The sign goes on the double, not on the long: -0L is 0L, and a
        // driver that turns "-0.0" into 0.0 has quietly dropped a sign the JDK
        // keeps. The test caught exactly that.
        double value = mantissa;
        if (negative) {
            value = -value;
        }
        return fraction <= 0 ? value : value / EXACT_POWERS[fraction];
    }

    /**
     * The {@code BigDecimal} written at {@code offset} as text, read out of
     * {@code scratch} rather than out of a fresh {@code String}.
     *
     * <p>{@code BigDecimal} can be built from a {@code char[]} directly, so the
     * JDK's own parser does the work and the only thing saved is the object -
     * which is the thing worth saving, because it is one per value. The caller
     * owns the array and keeps it across rows; it must be at least
     * {@code length} long.
     *
     * <p>Measured over a hundred thousand money-shaped values: 3.57 ms through
     * a {@code String}, <b>2.16 ms</b> this way.
     */
    public static BigDecimal bigDecimal(WireBuffer buffer, int offset, int length,
                                        char[] scratch) { // seclume-allow: a column value on its way to a BigDecimal, never a secret
        int start = 0;
        int end = length;
        // trim(), which the String path did, and which a value padded by a
        // server still needs.
        while (start < end && (buffer.getByte(offset + start) & 0xff) <= ' ') {
            start++;
        }
        while (end > start && (buffer.getByte(offset + end - 1) & 0xff) <= ' ') {
            end--;
        }
        for (int i = start; i < end; i++) {
            scratch[i - start] = (char) (buffer.getByte(offset + i) & 0xff);
        }
        return new BigDecimal(scratch, 0, end - start);
    }

    /** The bytes as a {@code String} - only on the paths that cannot avoid it. */
    private static String text(WireBuffer buffer, int offset, int length) {
        byte[] bytes = new byte[length]; // seclume-allow: user payload on its way to a number, not a secret
        for (int i = 0; i < length; i++) {
            bytes[i] = buffer.getByte(offset + i);
        }
        return new String(bytes, StandardCharsets.UTF_8); // seclume-allow: user payload, not a secret
    }

    private static int digit(int character) {
        int digit = character - '0';
        if (digit < 0 || digit > 9) {
            throw new NumberFormatException("not a digit in a number in text format");
        }
        return digit;
    }
}
