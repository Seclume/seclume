package space.seclume.diff;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.sql.Date;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Values nobody would type into a test by hand.
 *
 * <p>E1 showed that both drivers agree on every value a person thinks to
 * write down, and disagree on the ones a person does not - a
 * {@code bigint unsigned} at the top of its range came back as -1, and the
 * hand-written corpus had no such value in it because nobody sits down and
 * decides to try 18446744073709551615.
 *
 * <p>So the corpus is generated instead. Each type gets its <b>boundaries</b>
 * first, because that is where codecs break and a random draw almost never
 * lands there, and then random draws to cover the space between them. The two
 * halves answer different questions: the boundaries ask "is the obvious edge
 * handled", the draws ask "is there an edge nobody thought of".
 *
 * <h2>Reproducible on purpose</h2>
 *
 * <p>Everything comes out of one seeded {@link Random}, and the seed is
 * printed with every run and every failure. A property-based test that cannot
 * be replayed is a test that reports a bug once and then hides it.
 */
final class Values {

    private Values() {
    }

    /** Fills a list to {@code count} with boundaries first, then draws. */
    private static List<Object> corpus(List<Object> boundaries, int count, Random random,
            java.util.function.Supplier<Object> draw) {
        List<Object> values = new ArrayList<>(boundaries);
        while (values.size() < count) {
            values.add(draw.get());
        }
        // A null in the middle rather than at the end: a driver that handles
        // the last row differently would otherwise never be asked.
        if (values.size() > 2) {
            values.set(values.size() / 2, null);
        }
        return values.subList(0, count);
    }

    static List<Object> int32(int count, Random random) {
        return corpus(List.of(0, 1, -1, Integer.MIN_VALUE, Integer.MAX_VALUE,
                        Integer.MIN_VALUE + 1, Integer.MAX_VALUE - 1),
                count, random, random::nextInt);
    }

    static List<Object> int64(int count, Random random) {
        return corpus(List.of(0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE,
                        (long) Integer.MAX_VALUE, (long) Integer.MAX_VALUE + 1),
                count, random, random::nextLong);
    }

    /**
     * Doubles, including the ones that are not numbers.
     *
     * <p>Infinity and NaN are left out: no SQL numeric column can hold them
     * and the insert would fail before any comparison happened. Negative zero
     * is in, because it is a real double that most codecs render as "0" and a
     * few as "-0".
     */
    static List<Object> float64(int count, Random random) {
        return float64(count, random, Double.MAX_VALUE);
    }

    /**
     * The same, kept inside a magnitude the target can be bound with.
     *
     * <p>For Oracle. {@code setObject} on a {@code Double} goes through
     * {@code NUMBER} in ojdbc whatever the column is, so anything past about
     * 1e125 throws "Overflow" before it reaches the server - even into a
     * {@code binary_double}, which holds it comfortably. Bounding the corpus
     * keeps the run measuring the two drivers rather than that limit; the
     * limit itself is written down where the column is declared.
     */
    static List<Object> float64(int count, Random random, double limit) {
        List<Object> boundaries = new ArrayList<>(List.of(
                0.0d, -0.0d, 1.0d, -1.0d, 1.0d / 3.0d, 0.1d + 0.2d));
        if (limit >= Double.MAX_VALUE) {
            boundaries.addAll(List.of(Double.MIN_VALUE, Double.MAX_VALUE, -Double.MAX_VALUE));
        } else {
            boundaries.addAll(List.of(limit, -limit, 1.0d / limit));
        }
        int maxExponent = limit >= Double.MAX_VALUE ? 20
                : (int) Math.floor(Math.log10(limit));
        return corpus(List.copyOf(boundaries), count, random, () -> {
            double value = random.nextDouble()
                    * Math.pow(10, random.nextInt(2 * maxExponent + 1) - maxExponent);
            return random.nextBoolean() ? value : -value;
        });
    }

    /**
     * Exact numerics that fit {@code numeric(precision, scale)}.
     *
     * <p>Generated to fit rather than clipped afterwards: a value the column
     * cannot hold makes the server round or refuse, and then the test is
     * measuring the server's rounding rather than the drivers' codecs. The
     * rounding case is worth testing, but as a deliberate case and not as an
     * accident in every row.
     */
    static List<Object> decimal(int count, Random random, int precision, int scale) {
        BigDecimal max = BigDecimal.ONE
                .movePointRight(precision - scale)
                .subtract(BigDecimal.ONE.movePointLeft(scale));
        List<Object> boundaries = List.of(
                BigDecimal.ZERO.setScale(scale),
                BigDecimal.ONE.setScale(scale),
                BigDecimal.ONE.negate().setScale(scale),
                max,
                max.negate(),
                BigDecimal.ONE.movePointLeft(scale),            // the smallest step
                BigDecimal.ONE.movePointLeft(scale).negate());
        return corpus(boundaries, count, random, () -> {
            BigInteger unscaled = new BigInteger(precision * 3, random)
                    .mod(BigInteger.TEN.pow(precision));
            BigDecimal value = new BigDecimal(unscaled, scale);
            return random.nextBoolean() ? value : value.negate();
        });
    }

    /**
     * Text, with the parts of Unicode that break naive codecs.
     *
     * <p>Not "random letters": the interesting cases are a combining mark
     * that makes two code points look like one character, a surrogate pair
     * that is one character in two {@code char}s, and a right-to-left mark
     * that is invisible. A driver that counts characters where it should
     * count bytes, or truncates in the middle of a pair, fails on these and
     * on nothing else.
     */
    static List<Object> text(int count, Random random, int maxLength) {
        List<Object> boundaries = new ArrayList<>(List.of(
                "",
                " ",
                "  trailing and leading  ",
                "á",                       // a + combining acute
                "😀",                  // an emoji: one character, two chars
                "‏‎",                  // right-to-left and left-to-right marks
                "line\nbreak\ttab",
                "quote'double\"backslash\\",
                "äöüß",
                "中文测试"));
        boundaries.removeIf(v -> ((String) v).length() > maxLength);
        return corpus(List.copyOf(boundaries), count, random,
                () -> randomString(random, maxLength));
    }

    /**
     * A random string over an alphabet that spans the awkward planes.
     *
     * <p>A surrogate pair is emitted whole or not at all - half of one is not
     * a string Java can hold, let alone a database, and generating one would
     * be testing the generator.
     */
    private static String randomString(Random random, int maxLength) {
        int length = random.nextInt(Math.min(maxLength, 24) + 1);
        StringBuilder text = new StringBuilder(length);
        while (text.length() < length) {
            int pick = random.nextInt(10);
            if (pick < 5) {
                text.append((char) ('a' + random.nextInt(26)));
            } else if (pick < 7) {
                text.append((char) (0xc0 + random.nextInt(0x17e - 0xc0)));   // latin extended
            } else if (pick < 9) {
                text.append((char) (0x4e00 + random.nextInt(0x1000)));       // CJK
            } else if (text.length() + 2 <= length) {
                text.appendCodePoint(0x1f600 + random.nextInt(0x40));        // emoji
            } else {
                text.append('z');
            }
        }
        return text.toString();
    }

    static List<Object> bytes(int count, Random random, int maxLength) {
        List<Object> boundaries = List.of(
                new byte[0],
                new byte[] {0},
                new byte[] {0, 0, 0},
                new byte[] {(byte) 0xff},
                new byte[] {0x27, 0x5c, 0x00, 0x0a},              // quote, backslash, nul, LF
                new byte[] {(byte) 0xc3, (byte) 0x28});           // invalid UTF-8 on purpose
        return corpus(boundaries, count, random, () -> {
            byte[] value = new byte[random.nextInt(Math.min(maxLength, 32) + 1)];
            random.nextBytes(value);
            return value;
        });
    }

    /**
     * Dates, including the ones calendars argue about.
     *
     * <p>1582 is where the Julian and Gregorian calendars part company and
     * {@code java.sql.Date} still carries that seam; the leap day and the ends
     * of years are where off-by-one lives.
     */
    static List<Object> dates(int count, Random random) {
        List<Object> boundaries = List.of(
                Date.valueOf("1970-01-01"),
                Date.valueOf("1969-12-31"),
                Date.valueOf("2000-02-29"),
                Date.valueOf("2024-02-29"),
                Date.valueOf("1900-01-01"),
                Date.valueOf("2038-01-19"),                       // the 32-bit seam
                Date.valueOf("9999-12-31"));
        return corpus(boundaries, count, random, () -> Date.valueOf(
                LocalDate.ofEpochDay(random.nextInt(365 * 200) - 365 * 50)));
    }

    /**
     * Timestamps, to the microsecond the servers actually keep.
     *
     * <p>Nanoseconds are not generated: PostgreSQL and MySQL both store
     * microseconds, so a nanosecond value measures the server's rounding and
     * not the drivers. The rounding case belongs in a test that says so.
     */
    static List<Object> timestamps(int count, Random random) {
        List<Object> boundaries = List.of(
                Timestamp.valueOf("1970-01-01 00:00:00"),
                Timestamp.valueOf("1970-01-01 00:00:00.000001"),
                Timestamp.valueOf("1999-12-31 23:59:59.999999"),
                Timestamp.valueOf("2000-01-01 00:00:00"),
                Timestamp.valueOf("2024-02-29 12:00:00.500000"),
                Timestamp.valueOf("2038-01-19 03:14:07"));
        return corpus(boundaries, count, random, () -> {
            Timestamp value = new Timestamp(
                    (long) (random.nextInt(365 * 60) - 365 * 10) * 86_400_000L
                            + random.nextInt(86_400_000));
            value.setNanos(random.nextInt(1_000_000) * 1000);     // microsecond resolution
            return value;
        });
    }

    /** A decimal that the column cannot hold, so the server has to round. */
    static BigDecimal tooPrecise(int scale) {
        return BigDecimal.ONE.movePointLeft(scale + 1).setScale(scale + 1, RoundingMode.UNNECESSARY);
    }
}
