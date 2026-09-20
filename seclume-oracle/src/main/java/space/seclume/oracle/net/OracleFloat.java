package space.seclume.oracle.net;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * {@code BINARY_FLOAT} and {@code BINARY_DOUBLE} on the wire.
 *
 * <p>These are IEEE 754 numbers and not Oracle's own decimal format, but the
 * bytes are not the IEEE bytes: Oracle transforms them so that the byte order
 * sorts the same way the numbers do, which is what lets an index over the
 * column work. The transformation is small and exact:
 *
 * <ul>
 *   <li>a value that is not negative has its <b>sign bit set</b>,</li>
 *   <li>a negative value has <b>all its bits flipped</b>.</li>
 * </ul>
 *
 * <p>Reading is therefore: top bit set means clear it, otherwise flip
 * everything. Nothing about it is lossy in either direction - what the
 * application wrote is what it reads.
 *
 * <p>This existed nowhere in the driver, which is why an entity with an
 * ordinary Java {@code double} in it could not be read at all: Hibernate maps
 * one to {@code binary_double}, the bytes were then parsed as text, and the
 * driver said "column 11 is not a number".
 */
public final class OracleFloat {

    private OracleFloat() {
    }

    /** Whether a column carries one of the two. */
    public static boolean isBinaryFloat(int type) {
        return type == OracleColumn.TYPE_BINARY_FLOAT
                || type == OracleColumn.TYPE_BINARY_DOUBLE;
    }

    /** The value of a {@code BINARY_DOUBLE} (eight bytes) or {@code BINARY_FLOAT} (four). */
    public static double toDouble(MemorySegment in, int at, int length) {
        long bits = 0;
        for (int i = 0; i < length; i++) {
            bits = (bits << 8) | (in.get(ValueLayout.JAVA_BYTE, at + i) & 0xffL);
        }
        if (length == 4) {
            int value = (int) bits;
            value = (value & 0x80000000) != 0 ? value & 0x7fffffff : ~value;
            return Float.intBitsToFloat(value);
        }
        bits = (bits & 0x8000000000000000L) != 0 ? bits & 0x7fffffffffffffffL : ~bits;
        return Double.longBitsToDouble(bits);
    }

    /** The bytes of a value, in the same transformed order. */
    public static void encode(space.seclume.internal.WireBuffer out,
                              double value, boolean single) {
        if (single) {
            int bits = Float.floatToRawIntBits((float) value);
            bits = bits < 0 ? ~bits : bits | 0x80000000;
            out.putByte((byte) 4);
            for (int shift = 24; shift >= 0; shift -= 8) {
                out.putByte((byte) (bits >>> shift));
            }
            return;
        }
        long bits = Double.doubleToRawLongBits(value);
        bits = bits < 0 ? ~bits : bits | 0x8000000000000000L;
        out.putByte((byte) 8);
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.putByte((byte) (bits >>> shift));
        }
    }
}
