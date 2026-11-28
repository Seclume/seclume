package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * getLong on SQL Server: a float beyond a long was cast to Long.MAX_VALUE -
 * a wrong number that looks like one - and a DECIMAL(30) beyond a long was
 * "not a number". Both are out of range now; a fraction stays no long.
 */
class TdsLongRangeTest {

    private static WireBuffer flt8(double value) {
        WireBuffer in = new WireBuffer(16);
        long bits = Double.doubleToRawLongBits(value);
        for (int i = 0; i < 8; i++) {
            in.putByte((byte) (bits >>> (8 * i)));             // little-endian, as TDS sends it
        }
        return in;
    }

    @Test
    void aFloatBeyondALongIsOutOfRangeNotSaturated() {
        for (double value : new double[] {1e30, -1e30, 0x1p63, Double.NaN,
            Double.POSITIVE_INFINITY}) {
            try (WireBuffer in = flt8(value)) {
                assertThrows(ArithmeticException.class,
                        () -> TdsValues.asLong(in, TdsTypes.FLT8, 0, 8), String.valueOf(value));
            }
        }
        try (WireBuffer in = flt8(-0x1p63)) {
            assertEquals(Long.MIN_VALUE, TdsValues.asLong(in, TdsTypes.FLT8, 0, 8));
        }
        try (WireBuffer in = flt8(12.9)) {
            assertEquals(12, TdsValues.asLong(in, TdsTypes.FLT8, 0, 8), "truncated, as before");
        }
    }

    @Test
    void aWholeNumberBeyondALongIsOutOfRangeAndAFractionIsNoLong() {
        assertEquals(42, TdsValues.wholeNumber("42"));
        assertEquals(42, TdsValues.wholeNumber("42.000"));
        assertThrows(ArithmeticException.class,
                () -> TdsValues.wholeNumber("18446744073709551621"));
        assertThrows(ArithmeticException.class,
                () -> TdsValues.wholeNumber("-9223372036854775809"));
        assertThrows(NumberFormatException.class, () -> TdsValues.wholeNumber("12.5"));
        assertThrows(NumberFormatException.class, () -> TdsValues.wholeNumber("twelve"));
    }
}
