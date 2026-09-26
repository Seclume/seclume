package space.seclume.oracle.net;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.internal.WireBuffer;

/**
 * Oracle's {@code NUMBER} on the wire.
 *
 * <p>Oracle does not send numbers as integers or as floating point but in a
 * format of its own: one exponent byte, then digits to <b>base 100</b>. The
 * format is order-preserving - two numbers compare correctly by comparing
 * their bytes - which is why the index works and why it looks as odd as it
 * does.
 *
 * <p>The rules:
 *
 * <ul>
 *   <li>A single {@code 0x80} is the zero.</li>
 *   <li><b>Positive:</b> the exponent is {@code b0 - 193}, and every following
 *       byte is its base-100 digit <b>plus one</b>. So {@code c1 2b} is
 *       exponent 0 and the digit 42 - the number 42.</li>
 *   <li><b>Negative:</b> everything is complemented. The exponent is
 *       {@code 62 - b0}, a digit is {@code 101 - bi}, and a terminating
 *       {@code 0x66} may follow which is not a digit. Without that
 *       complement the byte order would sort negative numbers the wrong way
 *       round.</li>
 * </ul>
 *
 * <p>The digit plus one exists so that no digit byte is zero - otherwise a
 * value could contain a zero byte, and the format is used in places where
 * that would end a field.
 *
 * <p>Decoding produces a {@code long} where the number is an integer, and
 * decimal text otherwise. Deliberately no {@code BigDecimal} on the way: the
 * caller who wants one builds it from the text, and the caller who calls
 * {@code getLong} never allocates anything at all.
 */
public final class OracleNumber {

    /** The largest number of mantissa bytes Oracle keeps. */
    private static final int MAX_DIGITS = 20;

    /**
     * Writes a whole number the way Oracle wants it, with its length in front.
     *
     * <p>The rules of the format read backwards: group the decimal digits in
     * twos from the decimal point, drop the groups that are zero at either
     * end, and what is left is the mantissa. The exponent counts the groups
     * before the point.
     */
    public static void encode(WireBuffer out, long value) {
        if (value == 0) {
            out.putByte((byte) 1);
            out.putByte((byte) ZERO);
            return;
        }
        if (value == Long.MIN_VALUE) {
            // One value has no positive counterpart; the text path handles it
            // without a detour through an unsigned type.
            encodeText(out, "-9223372036854775808");
            return;
        }
        boolean positive = value > 0;
        long rest = positive ? value : -value;
        int[] groups = new int[MAX_DIGITS];
        int count = 0;
        while (rest > 0) {
            groups[count++] = (int) (rest % BASE);
            rest /= BASE;
        }
        // The groups came out least significant first; the wire wants them the
        // other way round, and the trailing zero groups are not sent at all.
        int[] mantissa = new int[count];
        for (int i = 0; i < count; i++) {
            mantissa[i] = groups[count - 1 - i];
        }
        int length = count;
        while (length > 1 && mantissa[length - 1] == 0) {
            length--;
        }
        write(out, positive, count - 1, mantissa, length);
    }

    /**
     * A decimal given as its unscaled digits and scale - {@code 12.50} as
     * 1250 and 2 - without going through text.
     *
     * <p>A BigDecimal bound as a parameter went through toPlainString and back
     * into digits, a String and a builder per value; in a batch of five
     * thousand rows that was the largest single cost on the client. Base 100
     * wants the point between two groups, so an odd scale takes one more
     * digit; what does not fit a long then goes the text way.
     */
    public static void encodeScaled(WireBuffer out, long unscaled, int scale) {
        if (unscaled == 0) {
            out.putByte((byte) 1);
            out.putByte((byte) ZERO);
            return;
        }
        long value = unscaled;
        int even = scale;
        if (even % 2 != 0) {
            if (Math.abs(value) > Long.MAX_VALUE / 10) {
                encodeText(out, java.math.BigDecimal.valueOf(unscaled, scale).toPlainString());
                return;
            }
            value *= 10;
            even++;
        }
        if (even < 0 || value == Long.MIN_VALUE) {
            encodeText(out, java.math.BigDecimal.valueOf(unscaled, scale).toPlainString());
            return;
        }
        boolean positive = value > 0;
        long rest = positive ? value : -value;
        int[] groups = new int[MAX_DIGITS]; // seclume-allow: digits of a bind value, never a secret
        int count = 0;
        while (rest > 0) {
            groups[count++] = (int) (rest % BASE);
            rest /= BASE;
        }
        int[] mantissa = new int[count]; // seclume-allow: digits of a bind value, never a secret
        for (int i = 0; i < count; i++) {
            mantissa[i] = groups[count - 1 - i];
        }
        int length = count;
        while (length > 1 && mantissa[length - 1] == 0) {
            length--;
        }
        write(out, positive, count - 1 - even / 2, mantissa, length);
    }

    /**
     * The same for a number that does not fit into a {@code long} - a decimal
     * with a point, or one with too many digits.
     *
     * @param decimal plain decimal notation, no exponent
     */
    public static void encodeText(WireBuffer out, String decimal) {
        String text = decimal.trim();
        boolean positive = !text.startsWith("-");
        if (text.startsWith("-") || text.startsWith("+")) {
            text = text.substring(1);
        }
        int point = text.indexOf('.');
        String whole = point < 0 ? text : text.substring(0, point);
        String fraction = point < 0 ? "" : text.substring(point + 1);

        // Pad both sides until the point sits between two groups.
        StringBuilder digits = new StringBuilder();
        if (whole.length() % 2 != 0) {
            digits.append('0');
        }
        digits.append(whole).append(fraction);
        if (fraction.length() % 2 != 0) {
            digits.append('0');
        }
        int wholeGroups = (whole.length() + 1) / 2;

        int total = digits.length() / 2;
        int[] all = new int[total];
        for (int i = 0; i < total; i++) {
            all[i] = (digits.charAt(i * 2) - '0') * 10 + (digits.charAt(i * 2 + 1) - '0');
        }
        int first = 0;
        while (first < total && all[first] == 0) {
            first++;                                   // a leading zero group only moves the point
        }
        if (first == total) {
            out.putByte((byte) 1);
            out.putByte((byte) ZERO);
            return;
        }
        int last = total;
        while (last > first + 1 && all[last - 1] == 0) {
            last--;
        }
        int length = Math.min(last - first, MAX_DIGITS);
        int[] mantissa = new int[length];
        System.arraycopy(all, first, mantissa, 0, length);
        write(out, positive, wholeGroups - first - 1, mantissa, length);
    }

    /**
     * The common tail: exponent byte, then the digits - complemented when the
     * number is negative, and closed by a terminator that is not a digit.
     */
    private static void write(WireBuffer out, boolean positive, int exponent,
                              int[] mantissa, int length) {
        boolean terminated = !positive && length < MAX_DIGITS;
        out.putByte((byte) (1 + length + (terminated ? 1 : 0)));
        out.putByte((byte) (positive ? POSITIVE_BIAS + exponent : NEGATIVE_BIAS - exponent));
        for (int i = 0; i < length; i++) {
            out.putByte((byte) (positive ? mantissa[i] + 1 : BASE + 1 - mantissa[i]));
        }
        if (terminated) {
            out.putByte((byte) NEGATIVE_TERMINATOR);
        }
    }

    /** The single byte that is the zero. */
    private static final int ZERO = 0x80;
    /** The exponent offset for positive numbers. */
    private static final int POSITIVE_BIAS = 193;
    /** For negative numbers the exponent is this minus the byte. */
    private static final int NEGATIVE_BIAS = 62;
    /** The byte that closes a negative number; it is not a digit. */
    private static final int NEGATIVE_TERMINATOR = 0x66;
    /** Digits count to base 100. */
    private static final int BASE = 100;

    private OracleNumber() {
    }

    /** Whether the value is the zero - a single byte. */
    public static boolean isZero(MemorySegment in, long at, int length) {
        return length == 0 || (length == 1 && byteAt(in, at) == ZERO);
    }

    /**
     * The value as an integer.
     *
     * <p>Digits after the decimal point are cut off, as
     * {@code ResultSet.getLong} prescribes. An exponent so large that the
     * value does not fit into a {@code long} is an error rather than a
     * silently wrong number.
     */
    public static long toLong(MemorySegment in, long at, int length) {
        if (isZero(in, at, length)) {
            return 0;
        }
        boolean positive = (byteAt(in, at) & 0x80) != 0;
        int exponent = exponentOf(in, at);
        long value = 0;
        int used = 0;
        for (int i = 1; i < length && used <= exponent; i++) {
            int b = byteAt(in, at + i);
            if (!positive && b == NEGATIVE_TERMINATOR) {
                break;
            }
            value = value * BASE + digitOf(b, positive);
            used++;
        }
        // Trailing zero digits are not sent: 100 is one digit with an exponent
        // of one, so the missing places have to be multiplied back in.
        for (int i = used; i <= exponent; i++) {
            if (value > Long.MAX_VALUE / BASE) {
                throw new ArithmeticException("the number does not fit into a long");
            }
            value *= BASE;
        }
        return positive ? value : -value;
    }

    /**
     * The value as decimal text, without rounding.
     *
     * <p>Text and not {@code double}: a {@code NUMBER(38)} has more digits
     * than a {@code double} has, and turning it into one loses them without
     * saying so.
     */
    public static String toText(MemorySegment in, long at, int length) {
        if (isZero(in, at, length)) {
            return "0";
        }
        boolean positive = (byteAt(in, at) & 0x80) != 0;
        int exponent = exponentOf(in, at);

        StringBuilder digits = new StringBuilder(); // seclume-allow: a numeric payload value, not a secret
        int first = -1;
        for (int i = 1; i < length; i++) {
            int b = byteAt(in, at + i);
            if (!positive && b == NEGATIVE_TERMINATOR) {
                break;
            }
            int digit = digitOf(b, positive);
            if (first < 0) {
                // The leading digit carries the magnitude and is written as it
                // is; every one after it is a pair and gets padded.
                first = digit;
                digits.append(digit);
            } else {
                if (digit < 10) {
                    digits.append('0');
                }
                digits.append(digit);
            }
        }

        // The point sits after exponent+1 base-100 digits, that is after twice
        // as many decimal ones - minus the padding the leading digit did not
        // get.
        int integerDigits = (exponent + 1) * 2 - (first < 10 ? 1 : 0);
        String text = withPoint(digits.toString(), integerDigits);
        return positive ? text : "-" + text;
    }

    /** The value as a floating-point number - for {@code getDouble}. */
    public static double toDouble(MemorySegment in, long at, int length) {
        return Double.parseDouble(toText(in, at, length));
    }

    /** The exponent: biased for positive numbers, complemented for negative. */
    private static int exponentOf(MemorySegment in, long at) {
        int first = byteAt(in, at);
        return (first & 0x80) != 0 ? first - POSITIVE_BIAS : NEGATIVE_BIAS - first;
    }

    /** One base-100 digit; negative numbers store it complemented. */
    private static int digitOf(int b, boolean positive) {
        return positive ? b - 1 : BASE + 1 - b;
    }

    /** Puts the decimal point in, padding with zeroes on either side. */
    private static String withPoint(String digits, int integerDigits) {
        StringBuilder text = new StringBuilder(); // seclume-allow: a numeric payload value, not a secret
        if (integerDigits <= 0) {
            text.append("0.");
            text.append("0".repeat(-integerDigits));
            text.append(digits);
        } else if (integerDigits >= digits.length()) {
            text.append(digits);
            text.append("0".repeat(integerDigits - digits.length()));
        } else {
            text.append(digits, 0, integerDigits).append('.')
                    .append(digits, integerDigits, digits.length());
        }
        return trimZeroes(text.toString());
    }

    /** Trailing zeroes after a decimal point say nothing and go. */
    private static String trimZeroes(String text) {
        if (text.indexOf('.') < 0) {
            return text;
        }
        int end = text.length();
        while (end > 0 && text.charAt(end - 1) == '0') {
            end--;
        }
        if (end > 0 && text.charAt(end - 1) == '.') {
            end--;
        }
        return text.substring(0, end);
    }

    private static int byteAt(MemorySegment in, long at) {
        return in.get(ValueLayout.JAVA_BYTE, at) & 0xff;
    }
}
