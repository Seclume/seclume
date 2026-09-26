package space.seclume.oracle.net;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigDecimal;
import java.sql.SQLException;

/**
 * Oracle's {@code VECTOR} (23ai), from the image a LOB read hands back, as the
 * text ojdbc and the server write: {@code [1.0E+000,2.5E+000]} for the
 * floating formats, {@code [1,2,3]} for {@code INT8} and {@code BINARY}.
 *
 * <p>The image: a magic byte (0xDB), a version, two bytes of flags, one of
 * format, four of element count, then - when the flags say so - eight bytes
 * of a precomputed norm, then the elements. The floating ones are stored as
 * {@code BINARY_FLOAT} and {@code BINARY_DOUBLE} are, transformed to sort as
 * numbers do. Whether the norm is there is read off the length rather than off
 * a flag bit, so a flag this does not know about cannot shift the elements. A
 * sparse vector is refused by name.
 */
public final class OracleVector {

    private static final int MAGIC = 0xdb;
    private static final int HEADER = 9;
    private static final int NORM = 8;

    private static final int FLOAT32 = 2;
    private static final int FLOAT64 = 3;
    private static final int INT8 = 4;
    private static final int BINARY = 5;

    private OracleVector() {
    }

    public static String toText(MemorySegment in, long at, int length) throws SQLException {
        if (length < HEADER || byteAt(in, at) != MAGIC) {
            throw new SQLException("not a VECTOR image", "22000");
        }
        int format = byteAt(in, at + 4);
        long count = 0;
        for (int i = 0; i < 4; i++) {
            count = (count << 8) | byteAt(in, at + 5 + i);
        }
        int width = switch (format) {
            case FLOAT32 -> 4;
            case FLOAT64 -> 8;
            case INT8, BINARY -> 1;
            default -> throw new SQLException("a VECTOR of format " + format
                    + ", which this driver does not read", "0A000");
        };
        if (format == BINARY) {
            count /= 8;                                  // the count is in bits
        }
        long elements = at + HEADER;
        long rest = length - HEADER;
        if (rest == count * width + NORM) {
            elements += NORM;
        } else if (rest != count * width) {
            throw new SQLException("a sparse VECTOR, which this driver does not read yet",
                    "0A000");
        }
        // Sixteen characters an element is about what a FLOAT32 takes; sizing
        // for it once keeps the builder from growing and copying.
        StringBuilder text = new StringBuilder((int) Math.min(count * 16 + 2, 1 << 30)); // seclume-allow: a value on its way to the caller, not a secret
        char[] digits = new char[24]; // seclume-allow: digits of a vector element, never a secret
        text.append('[');
        for (long i = 0; i < count; i++) {
            if (i > 0) {
                text.append(',');
            }
            long p = elements + i * width;
            switch (format) {
                case FLOAT32 -> float32(text, (float) OracleFloat.toDouble(in, (int) p, 4));
                case FLOAT64 -> float64(text, OracleFloat.toDouble(in, (int) p, 8), digits);
                case INT8 -> text.append(in.get(ValueLayout.JAVA_BYTE, p));
                default -> text.append(byteAt(in, p));
            }
        }
        return text.append(']').toString();
    }

    /** Powers of ten that a double holds exactly. */
    private static final double[] TENS = new double[23];

    static {
        TENS[0] = 1;
        for (int i = 1; i < TENS.length; i++) {
            TENS[i] = TENS[i - 1] * 10;
        }
    }

    /**
     * A FLOAT32 to nine significant digits of the float itself -
     * {@code -1.00000005E-003} for {@code -0.001f}, as the server and ojdbc
     * write it. In long arithmetic, without a BigDecimal per element: an
     * embedding has a thousand and more of them. Only a value whose tenth
     * digit sits within a hair of a tie takes the exact way.
     */
    static void float32(StringBuilder text, float value) {
        if (value == 0) {
            text.append('0');                          // a bare 0, as ojdbc writes it
            return;
        }
        double magnitude = Math.abs((double) value);
        int exponent = (int) Math.floor(Math.log10(magnitude));
        double scaled = scale(magnitude, 8 - exponent);
        if (scaled < 1e8) {                            // log10 one too high
            exponent--;
            scaled = scale(magnitude, 8 - exponent);
        } else if (scaled >= 1e9) {                    // or one too low
            exponent++;
            scaled = scale(magnitude, 8 - exponent);
        }
        double fraction = scaled - Math.floor(scaled);
        long nine;
        if (Math.abs(fraction - 0.5) < 1e-6) {
            nine = new BigDecimal(magnitude).round(new java.math.MathContext(9))
                    .scaleByPowerOfTen(8 - exponent).longValue();
        } else {
            nine = (long) Math.floor(scaled + 0.5);
        }
        if (nine >= 1_000_000_000L) {                  // 9.99999999x rounded up
            nine /= 10;
            exponent++;
        }
        if (value < 0) {
            text.append('-');
        }
        long divisor = 100_000_000L;
        text.append((char) ('0' + nine / divisor)).append('.');
        long rest = nine % divisor;
        if (rest == 0) {
            text.append('0');
        } else {
            while (rest % 10 == 0) {
                rest /= 10;
                divisor /= 10;
            }
            for (divisor /= 10; divisor > 0; divisor /= 10) {
                text.append((char) ('0' + rest / divisor % 10));
            }
        }
        exponent(text, exponent);
    }

    private static double scale(double magnitude, int power) {
        if (power >= 0) {
            return power < TENS.length ? magnitude * TENS[power]
                    : magnitude * TENS[22] * Math.pow(10, power - 22);
        }
        return -power < TENS.length ? magnitude / TENS[-power] : magnitude / Math.pow(10, -power);
    }

    /**
     * A FLOAT64 in its shortest form - {@code 1.0E-001} for 0.1 - rewritten
     * from {@code Double.toString} into one digit, a point and the rest.
     */
    static void float64(StringBuilder text, double value, char[] digits) { // seclume-allow: digits of a vector element
        if (value == 0) {
            text.append('0');
            return;
        }
        String shortest = Double.toString(Math.abs(value));
        int e = shortest.indexOf('E');
        int mantissaEnd = e < 0 ? shortest.length() : e;
        int power = e < 0 ? 0 : Integer.parseInt(shortest, e + 1, shortest.length(), 10);
        int count = 0;
        int whole = mantissaEnd;
        for (int i = 0; i < mantissaEnd; i++) {
            char c = shortest.charAt(i);
            if (c == '.') {
                whole = i;
            } else {
                digits[count++] = c;
            }
        }
        int lead = 0;
        while (lead < count - 1 && digits[lead] == '0') {
            lead++;
        }
        int end = count;
        while (end > lead + 1 && digits[end - 1] == '0') {
            end--;
        }
        if (value < 0) {
            text.append('-');
        }
        text.append(digits[lead]).append('.');
        if (end - lead > 1) {
            text.append(digits, lead + 1, end - lead - 1);
        } else {
            text.append('0');
        }
        exponent(text, power + whole - 1 - lead);
    }

    /** "E+003", "E-300": a sign and three digits. */
    private static void exponent(StringBuilder text, int exponent) {
        int magnitude = Math.abs(exponent);
        text.append('E').append(exponent < 0 ? '-' : '+')
                .append((char) ('0' + magnitude / 100))
                .append((char) ('0' + magnitude / 10 % 10))
                .append((char) ('0' + magnitude % 10));
    }

    private static int byteAt(MemorySegment in, long at) {
        return in.get(ValueLayout.JAVA_BYTE, at) & 0xff;
    }
}
