package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Date;
import java.sql.Time;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Locale;
import java.util.SplittableRandom;
import java.util.TimeZone;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * A binary DATETIME read as fields must be the value its text was:
 * {@code Timestamp.valueOf}, {@code Date.valueOf} and {@code Time.valueOf} of
 * what {@link BinaryValues#timestampText} writes for the same bytes - the
 * path getTimestamp, getDate and getTime took before.
 */
@Isolated("sets the JVM's default time zone and locale")
class BinaryTemporalFieldsTest {

    private static final String[] ZONES = {"UTC", "Europe/Vienna", "America/Sao_Paulo",
        "Australia/Lord_Howe", "Pacific/Apia"};

    @Test
    void theFieldsAreTheValueTheTextWas() {
        TimeZone zoneBefore = TimeZone.getDefault();
        Locale localeBefore = Locale.getDefault();
        Locale.setDefault(Locale.forLanguageTag("ar-EG"));
        try {
            for (String zone : ZONES) {
                TimeZone.setDefault(TimeZone.getTimeZone(zone));
                SplittableRandom random = new SplittableRandom(zone.hashCode());
                int taken = 0;
                for (int round = 0; round < 40_000; round++) {
                    long year = random.nextInt(4) == 0 ? random.nextInt(10_000) : 1900 + random.nextInt(200);
                    int month = random.nextInt(14);
                    int day = random.nextInt(32);
                    int hour = random.nextInt(30);
                    int minute = random.nextInt(62);
                    int second = random.nextInt(62);
                    long micros = random.nextInt(6) == 0 ? -1 : random.nextInt(10) == 0
                            ? random.nextLong(1L << 32) : random.nextInt(1_000_000);
                    int decimals = random.nextInt(8);
                    LocalDateTime fields = BinaryValues.localDateTime(year, month, day, hour, minute, second,
                            micros, decimals);
                    if (fields == null) {
                        continue;
                    }
                    taken++;
                    String text = BinaryValues.timestampText(year, month, day, hour, minute, second, micros,
                            decimals);
                    Timestamp expected = Timestamp.valueOf(text);
                    Timestamp direct = Timestamp.valueOf(fields);
                    assertEquals(expected.getTime(), direct.getTime(), zone + " " + text);
                    assertEquals(expected.getNanos(), direct.getNanos(), zone + " " + text);
                    assertEquals(Date.valueOf(text.substring(0, 10)), Date.valueOf(fields.toLocalDate()), text);
                    assertEquals(Time.valueOf(text.substring(11, 19)), Time.valueOf(fields.toLocalTime()), text);
                }
                assertTrue(taken > 15_000, zone + ": " + taken + " values were read as fields");
            }
        } finally {
            TimeZone.setDefault(zoneBefore);
            Locale.setDefault(localeBefore);
        }
    }

    @Test
    void theFractionIsCutToTheDeclaredDigitsAsTheTextIs() {
        assertEquals(123_000_000, BinaryValues.localDateTime(2026, 9, 24, 13, 14, 15, 123_456, 3).getNano());
        assertEquals(100_000_000, BinaryValues.localDateTime(2026, 9, 24, 13, 14, 15, 123_456, 1).getNano());
        assertEquals(123_456_000, BinaryValues.localDateTime(2026, 9, 24, 13, 14, 15, 123_456, 6).getNano());
        // No declared digits - a computed value - keeps all six, as the text does.
        assertEquals(123_456_000, BinaryValues.localDateTime(2026, 9, 24, 13, 14, 15, 123_456, 0).getNano());
        assertEquals(123_456_000, BinaryValues.localDateTime(2026, 9, 24, 13, 14, 15, 123_456, 31).getNano());
        assertEquals(0, BinaryValues.localDateTime(2026, 9, 24, 13, 14, 15, -1, 3).getNano());
    }

    @Test
    void whatTheTextHasToSayGoesTheGeneralWay() {
        assertNull(BinaryValues.localDateTime(0, 0, 0, 0, 0, 0, -1, 0));           // the zero date
        assertNull(BinaryValues.localDateTime(2026, 2, 30, 0, 0, 0, -1, 0));
        assertNull(BinaryValues.localDateTime(1000, 2, 29, 0, 0, 0, -1, 0));       // a Julian leap day
        assertNull(BinaryValues.localDateTime(2026, 1, 1, 24, 0, 0, -1, 0));
        assertNull(BinaryValues.localDateTime(2026, 1, 1, 0, 60, 0, -1, 0));
        assertNull(BinaryValues.localDateTime(2026, 1, 1, 0, 0, 60, -1, 0));
        assertNull(BinaryValues.localDateTime(10_000, 1, 1, 0, 0, 0, -1, 0));
        assertNull(BinaryValues.localDateTime(2026, 1, 1, 0, 0, 0, 1_000_000, 6));
        assertNull(BinaryValues.localDateTime(2026, 13, 1, 0, 0, 0, -1, 0));
        assertNull(BinaryValues.localDateTime(2026, 1, 0, 0, 0, 0, -1, 0));
    }
}
