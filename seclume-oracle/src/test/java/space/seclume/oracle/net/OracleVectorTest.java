package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigDecimal;
import java.math.MathContext;
import java.util.SplittableRandom;

import org.junit.jupiter.api.Test;

/**
 * The fast renderings of a vector's elements, held against the exact one.
 *
 * <p>The exact one - a BigDecimal per element - is what the server's text
 * says by definition and was measured too slow for an embedding of 1536
 * floats. The fast one works in doubles and longs; it has to give the same
 * text for every value, including the ones next to a rounding tie, the
 * smallest and the largest a float has.
 */
class OracleVectorTest {

    @Test
    void float32MatchesTheExactRenderingEverywhere() {
        SplittableRandom random = new SplittableRandom(20260924);
        for (int i = 0; i < 1_000_000; i++) {
            float value = Float.intBitsToFloat(random.nextInt());
            if (Float.isNaN(value) || Float.isInfinite(value)) {
                continue;
            }
            check32(value);
        }
        for (float value : new float[] {1f, -1f, 0.001f, -0.001f, 1234.5f, 3e30f, 0.1f,
                Float.MIN_VALUE, -Float.MIN_VALUE, Float.MIN_NORMAL, Float.MAX_VALUE,
                9.9999999e8f, 999999999f, 1e-10f, 1e10f, 123456789f, 0.5f, 16777215f,
                16777216f, 1.00000005e-3f, 2.99999989e30f}) {
            check32(value);
        }
        // Around every power of ten, where the digit count changes.
        for (int power = -45; power <= 38; power++) {
            float ten = (float) Math.pow(10, power);
            check32(ten);
            check32(Math.nextUp(ten));
            check32(Math.nextDown(ten));
        }
    }

    @Test
    void float64MatchesTheExactRenderingEverywhere() {
        SplittableRandom random = new SplittableRandom(20260925);
        char[] digits = new char[24];
        for (int i = 0; i < 1_000_000; i++) {
            double value = Double.longBitsToDouble(random.nextLong());
            if (Double.isNaN(value) || Double.isInfinite(value)) {
                continue;
            }
            check64(value, digits);
        }
        for (double value : new double[] {0.1, -2e-300, 1.5, 2, 1234.5, Double.MIN_VALUE,
                Double.MAX_VALUE, 1e22, 1e23, 0.001, 100, 1e-5}) {
            check64(value, digits);
        }
    }

    private static void check32(float value) {
        StringBuilder fast = new StringBuilder();
        OracleVector.float32(fast, value);
        assertEquals(exact(new BigDecimal((double) value).round(new MathContext(9))),
                fast.toString(), "float " + value);
    }

    private static void check64(double value, char[] digits) {
        StringBuilder fast = new StringBuilder();
        OracleVector.float64(fast, value, digits);
        assertEquals(exact(new BigDecimal(Double.toString(value))), fast.toString(),
                "double " + value);
    }

    /** The slow, obviously right way: one digit, a point, the rest, E and three. */
    private static String exact(BigDecimal value) {
        if (value.signum() == 0) {
            return "0";
        }
        value = value.stripTrailingZeros();
        String digits = value.unscaledValue().abs().toString();
        int exponent = digits.length() - 1 - value.scale();
        return (value.signum() < 0 ? "-" : "") + digits.charAt(0) + "."
                + (digits.length() > 1 ? digits.substring(1) : "0")
                + "E" + String.format("%+04d", exponent);
    }
}
