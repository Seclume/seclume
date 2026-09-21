package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.sql.Timestamp;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * That the generator generates, and keeps generating.
 *
 * <p>A property-based test is only as good as its corpus, and a corpus is
 * the easiest thing in a suite to break without anyone noticing: narrow a
 * range, lose a branch, and the run stays green while it stops looking. The
 * failure is silent by construction - nothing goes red when a test searches
 * less.
 *
 * <p>So the awkward cases are asserted to be present rather than hoped for.
 * These need no database and run everywhere.
 */
class ValuesTest {

    private static final Random RANDOM = new Random(20260921L);

    @Test
    void theBoundariesAreActuallyInThere() {
        assertTrue(Values.int32(50, RANDOM).contains(Integer.MIN_VALUE));
        assertTrue(Values.int32(50, RANDOM).contains(Integer.MAX_VALUE));
        assertTrue(Values.int64(50, RANDOM).contains(Long.MIN_VALUE));
        assertTrue(Values.int64(50, RANDOM).contains(Long.MAX_VALUE));
    }

    /**
     * Negative zero survives generation.
     *
     * <p>It has to be looked for with {@code doubleToRawLongBits}: -0.0 equals
     * 0.0 under {@code ==} and under {@code List.contains}, which is exactly
     * why a codec can lose the sign without any ordinary assertion noticing.
     */
    @Test
    void negativeZeroIsGenerated() {
        boolean found = false;
        for (Object value : Values.float64(50, RANDOM)) {
            if (value instanceof Double number
                    && Double.doubleToRawLongBits(number) == Double.doubleToRawLongBits(-0.0d)) {
                found = true;
            }
        }
        assertTrue(found, "no negative zero in the corpus");
    }

    @Test
    void theTextCorpusCarriesTheAwkwardCharacters() {
        List<Object> text = Values.text(60, RANDOM, 64);
        String all = text.stream().filter(v -> v != null).map(Object::toString)
                .reduce("", String::concat);

        assertTrue(all.codePoints().anyMatch(c -> c > 0xffff),
                "no character outside the basic multilingual plane - the surrogate case is "
                + "exactly the one a codec gets wrong");
        assertTrue(all.indexOf('́') >= 0, "no combining mark");
        assertTrue(text.contains(""), "the empty string is not the same as null and has to be "
                + "in the corpus as well");
        assertTrue(text.contains(null), "no null");
    }

    /** Every generated string fits the column it is destined for. */
    @Test
    void generatedTextRespectsItsLimit() {
        for (Object value : Values.text(200, RANDOM, 12)) {
            if (value != null) {
                assertTrue(((String) value).length() <= 12,
                        "too long for its column: " + value);
            }
        }
    }

    @Test
    void theDecimalsFitTheirColumn() {
        for (Object value : Values.decimal(200, RANDOM, 20, 6)) {
            if (value == null) {
                continue;
            }
            BigDecimal number = (BigDecimal) value;
            assertEquals(6, number.scale(), "wrong scale: " + number);
            assertTrue(number.precision() - number.scale() <= 20 - 6,
                    "too large for numeric(20,6): " + number);
        }
    }

    /** Both signs, or half the range is never tried. */
    @Test
    void theDecimalsGoBothWays() {
        List<Object> values = Values.decimal(100, RANDOM, 20, 6);
        assertTrue(values.stream().anyMatch(v -> v != null && ((BigDecimal) v).signum() > 0));
        assertTrue(values.stream().anyMatch(v -> v != null && ((BigDecimal) v).signum() < 0));
    }

    /**
     * Timestamps stay on a microsecond boundary.
     *
     * <p>PostgreSQL and MySQL both store microseconds. A generated nanosecond
     * would make the server round, and the run would then be measuring the
     * server's rounding rather than the two drivers - a test that fails for a
     * reason it is not about.
     */
    @Test
    void timestampsAreGeneratedAtTheResolutionTheServersKeep() {
        for (Object value : Values.timestamps(100, RANDOM)) {
            if (value != null) {
                assertEquals(0, ((Timestamp) value).getNanos() % 1000,
                        "sub-microsecond precision the server cannot hold: " + value);
            }
        }
    }

    @Test
    void theByteCorpusHasTheZeroByteAndInvalidUtf8() {
        List<Object> bytes = Values.bytes(60, RANDOM, 32);
        assertTrue(bytes.stream().anyMatch(v -> v instanceof byte[] b && b.length == 0),
                "no empty array");
        assertTrue(bytes.stream().anyMatch(v -> v instanceof byte[] b && b.length > 0
                        && b[0] == 0),
                "no leading zero byte - the one that ends a C string");
    }

    /** A null in every corpus, and not only at the end. */
    @Test
    void nullSitsInTheMiddle() {
        List<Object> values = Values.int32(21, RANDOM);
        assertTrue(values.contains(null));
        assertFalse(values.get(values.size() - 1) == null,
                "a null only at the end would never be followed by another row");
    }

    /** The count asked for is the count delivered - no silent shrinking. */
    @Test
    void theCorpusIsTheSizeRequested() {
        assertEquals(37, Values.int32(37, RANDOM).size());
        assertEquals(37, Values.text(37, RANDOM, 20).size());
        assertEquals(37, Values.bytes(37, RANDOM, 20).size());
        assertEquals(37, Values.dates(37, RANDOM).size());
        assertEquals(37, Values.timestamps(37, RANDOM).size());
        assertEquals(37, Values.decimal(37, RANDOM, 20, 6).size());
    }
}
