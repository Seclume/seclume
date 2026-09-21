package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.internal.WireBuffer;

/**
 * The digits of a number, read eight bytes at a time.
 *
 * <p>Every integer a PostgreSQL or MySQL text result carries comes through
 * here, so the interesting cases are not the values but the <b>positions</b>:
 * the wide read may only happen where eight bytes are still inside the buffer,
 * and the last value in a block is exactly where they are not. A version that
 * ignores that reads past the end - which on a {@code MemorySegment} is an
 * exception rather than a wrong answer, and one that would land on whatever
 * query happened to be reading the last row.
 */
class TextNumberTest {

    @ParameterizedTest
    @ValueSource(strings = {
        "0", "1", "9", "42", "-1", "-42",
        "1234567",                     // seven digits: one wide read, one short
        "12345678",                    // exactly eight
        "123456789",                   // eight and one more
        "9223372036854775807",         // Long.MAX_VALUE
        "-9223372036854775808",        // Long.MIN_VALUE
    })
    void readsTheSameNumberJavaWould(String text) {
        // Room to spare, so every read can take its eight bytes.
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putText(text);
            assertEquals(Long.parseLong(text),
                    TextNumber.decimal(buffer, 0, text.length()));
        }
    }

    /**
     * The same numbers written so that they end at the very last byte of the
     * buffer - the case the wide read is not allowed to take.
     */
    @ParameterizedTest
    @ValueSource(strings = {"7", "42", "-42", "1234567", "12345678", "123456789"})
    void readsANumberThatEndsAtTheEndOfTheBuffer(String text) {
        try (WireBuffer buffer = new WireBuffer(1)) {
            int capacity = buffer.capacity();
            // Pad so that the number ends on the buffer's very last byte.
            buffer.putText("0".repeat(capacity - text.length()) + text);
            int offset = capacity - text.length();
            assertEquals(capacity, buffer.position(),
                    "the buffer has to be exactly full, or this tests nothing");
            assertEquals(Long.parseLong(text),
                    TextNumber.decimal(buffer, offset, text.length()));
        }
    }

    /** A value in the middle of a block, with other cells around it. */
    @Test
    void readsAValueThatIsNotAtTheStart() {
        try (WireBuffer buffer = new WireBuffer(16)) {
            buffer.putText("1234|56789|7");
            assertEquals(1234, TextNumber.decimal(buffer, 0, 4));
            assertEquals(56789, TextNumber.decimal(buffer, 5, 5));
            assertEquals(7, TextNumber.decimal(buffer, 11, 1));
        }
    }

    /** An empty cell is zero - what the loop this replaced also answered. */
    @Test
    void anEmptyValueIsZero() {
        try (WireBuffer buffer = new WireBuffer(8)) {
            buffer.putText("1");
            assertEquals(0, TextNumber.decimal(buffer, 0, 0));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"1.5", "12x4", "abc", " 12", "12 ", "+7"})
    void refusesWhatIsNotAnInteger(String text) {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putText(text);
            assertThrows(NumberFormatException.class,
                    () -> TextNumber.decimal(buffer, 0, text.length()));
        }
    }

    /**
     * The fast path has to agree with the JDK's parser bit for bit.
     *
     * <p>Not "close enough": a driver that answers 0.1 + 1e-17 where every
     * other one answers 0.1 has changed the value, and the difference turns up
     * in a sum over a million rows. The comparison is therefore on the bits,
     * which also settles NaN without a special case.
     */
    @ParameterizedTest
    @ValueSource(strings = {
        "0", "1", "-1", "0.5", "-0.5", "5.", ".5", "0.1", "0.2", "0.3",
        "1234.56", "-1234.56", "999999999999999",      // fifteen digits: the last exact one
        "9999999999999999",                            // sixteen: falls back
        "0.000000000000001",                           // fifteen decimals
        "0.0000000000000000000001",                    // twenty-two: at the edge of the table
        "0.00000000000000000000001",                   // twenty-three: falls back
        "1e10", "1E10", "1.5e-7", "-2.5E+3",           // exponents: all fall back
        "NaN", "Infinity", "-Infinity",
        "0.0", "-0.0",                                 // the sign of zero has to survive
        "123456789012345.6",                           // sixteen digits across the point
    })
    void aDoubleIsTheSameAsTheJdkWouldParse(String text) {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putText(text);
            assertEquals(Double.doubleToLongBits(Double.parseDouble(text)),
                    Double.doubleToLongBits(TextNumber.decimalDouble(buffer, 0, text.length())),
                    "different from Double.parseDouble for \"" + text + "\"");
        }
    }

    /** The same, over values nobody would think to write down. */
    @Test
    void aDoubleAgreesWithTheJdkOverGeneratedValues() {
        java.util.Random random = new java.util.Random(20260921L);
        try (WireBuffer buffer = new WireBuffer(64)) {
            for (int i = 0; i < 20_000; i++) {
                long mantissa = random.nextLong(1L, 1_000_000_000_000_000_000L)
                        >> random.nextInt(0, 60);
                int scale = random.nextInt(0, 24);
                String text = new java.math.BigDecimal(java.math.BigInteger.valueOf(
                        random.nextBoolean() ? mantissa : -mantissa), scale).toPlainString();
                buffer.clear();
                buffer.putText(text);
                assertEquals(Double.doubleToLongBits(Double.parseDouble(text)),
                        Double.doubleToLongBits(
                                TextNumber.decimalDouble(buffer, 0, text.length())),
                        "different from Double.parseDouble for \"" + text + "\"");
            }
        }
    }

    /** What is not a number at all still has to be refused, not answered with zero. */
    @ParameterizedTest
    @ValueSource(strings = {"", "-", ".", "..", "1.2.3", "abc", "1x"})
    void refusesWhatIsNotADouble(String text) {
        try (WireBuffer buffer = new WireBuffer(64)) {
            buffer.putText(text);
            assertThrows(NumberFormatException.class,
                    () -> TextNumber.decimalDouble(buffer, 0, text.length()));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "0", "1", "-1", "0.5", "1234.56", "-1234.56", "0.00", "1.230",
        "123456789012345678901234567890.123456789",    // far past any primitive
        "  42  ",                                      // padding the String path trimmed
        "1E+10", "-2.5e-7",
    })
    void aBigDecimalIsTheSameAsTheJdkWouldParse(String text) {
        try (WireBuffer buffer = new WireBuffer(128)) {
            buffer.putText(text);
            char[] scratch = new char[text.length()];
            assertEquals(new java.math.BigDecimal(text.trim()),
                    TextNumber.bigDecimal(buffer, 0, text.length(), scratch),
                    "different from new BigDecimal for \"" + text + "\"");
        }
    }
}
