package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Locale;
import java.util.Random;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * DATE, DATETIME and TIME of the binary protocol as text: the same as the
 * {@code String.format} they were written with - which they no longer are,
 * for speed - and ASCII digits whatever the JVM's default locale.
 *
 * <p>{@code String.format("%04d", ...)} writes the default locale's digits:
 * under {@code ar-EG}, {@code th-TH-u-nu-thai} or {@code hi-IN-u-nu-deva} a
 * {@code DATETIME} read with {@code getString} from a prepared statement
 * came back in Arabic-Indic, Thai or Devanagari digits, which
 * {@code Timestamp.valueOf} and every other reader of SQL dates refuse.
 */
class BinaryTemporalTextTest {

    private Locale before;

    @BeforeEach
    void aLocaleWithItsOwnDigits() {
        before = Locale.getDefault();
        Locale.setDefault(Locale.forLanguageTag("ar-EG"));
    }

    @AfterEach
    void restore() {
        Locale.setDefault(before);
    }

    private static String fraction(long micros, int decimals) {
        String six = String.format(Locale.ROOT, ".%06d", micros);
        return decimals >= 1 && decimals < 6 ? six.substring(0, 1 + decimals) : six;
    }

    @Test
    void theTextIsWhatTheFormatWroteInAsciiDigits() {
        Random random = new Random(0x6d7973L);
        for (int round = 0; round < 50_000; round++) {
            long year = random.nextInt(3) == 0 ? random.nextInt(65536) : 1900 + random.nextInt(200);
            int month = random.nextInt(13);
            int day = random.nextInt(32);
            int hour = random.nextInt(256);
            int minute = random.nextInt(60);
            int second = random.nextInt(60);
            // The wire has four bytes for it; a server only sends below a million.
            long micros = random.nextInt(4) == 0 ? random.nextLong(1L << 32)
                    : random.nextInt(1_000_000);
            int decimals = random.nextInt(8);
            String date = String.format(Locale.ROOT, "%04d-%02d-%02d", year, month, day);
            assertEquals(date, BinaryValues.dateText(year, month, day));

            String base = String.format(Locale.ROOT, "%s %02d:%02d:%02d", date, hour, minute,
                    second);
            assertEquals(base, BinaryValues.timestampText(year, month, day, hour, minute, second,
                    -1, decimals));
            assertEquals(base + fraction(micros, decimals), BinaryValues.timestampText(year,
                    month, day, hour, minute, second, micros, decimals));

            boolean negative = random.nextBoolean();
            long hours = random.nextInt(3) == 0 ? random.nextLong(1L << 32) * 24 + hour : hour;
            String time = String.format(Locale.ROOT, "%s%02d:%02d:%02d", negative ? "-" : "",
                    hours, minute, second);
            assertEquals(time, BinaryValues.timeText(negative, hours, minute, second, -1,
                    decimals));
            assertEquals(time + fraction(micros, decimals), BinaryValues.timeText(negative,
                    hours, minute, second, micros, decimals));
        }
    }

    @Test
    void theEdgesAreWrittenAsBefore() {
        assertEquals("0000-00-00", BinaryValues.dateText(0, 0, 0));
        assertEquals("0009-01-02", BinaryValues.dateText(9, 1, 2));
        assertEquals("65535-12-31", BinaryValues.dateText(65535, 12, 31));
        assertEquals("2026-11-13 09:05:07.123", BinaryValues.timestampText(2026, 11, 13, 9, 5,
                7, 123456, 3));
        assertEquals("2026-11-13 09:05:07.000001", BinaryValues.timestampText(2026, 11, 13, 9,
                5, 7, 1, 6));
        assertEquals("-838:59:59", BinaryValues.timeText(true, 838, 59, 59, -1, 0));
        assertEquals("00:00:00.0", BinaryValues.timeText(false, 0, 0, 0, 0, 1));
    }
}
