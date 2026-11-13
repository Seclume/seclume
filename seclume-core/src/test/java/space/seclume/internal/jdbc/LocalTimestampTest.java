package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Timestamp;
import java.util.Locale;
import java.util.SplittableRandom;
import java.util.TimeZone;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * The direct path for a timestamp without an offset, held against
 * {@code Timestamp.valueOf(String)} - the way it replaces - in zones whose
 * calendars have gaps, overlaps, half hours and a missing day, and across the
 * Julian-Gregorian change of 1582.
 */
@Isolated("sets the JVM's default time zone")
class LocalTimestampTest {

    private static final String[] ZONES = {"UTC", "Europe/Vienna", "America/Sao_Paulo",
        "Australia/Lord_Howe", "Pacific/Apia", "Asia/Kolkata", "America/St_Johns", "Europe/Dublin"};

    @Test
    void everyValueIsTheTimestampTheJdkParserMakesOfIt() {
        TimeZone before = TimeZone.getDefault();
        try {
            for (String zone : ZONES) {
                TimeZone.setDefault(TimeZone.getTimeZone(zone));
                SplittableRandom random = new SplittableRandom(zone.hashCode());
                int taken = 0;
                for (int i = 0; i < 60_000; i++) {
                    String text = random.nextInt(5) == 0 ? edge(random) : generated(random);
                    taken += same(text) ? 1 : 0;
                }
                // Most generated values are well formed and take the direct path.
                assertTrue(taken > 40_000, zone + ": " + taken + " took the direct path");
            }
        } finally {
            TimeZone.setDefault(before);
        }
    }

    @Test
    void theCalendarsOddDaysAreTheJdksOddDays() {
        TimeZone before = TimeZone.getDefault();
        try {
            String[][] cases = {
                {"Europe/Vienna", "2026-03-29 02:30:00"},        // in the spring gap
                {"Europe/Vienna", "2026-10-25 02:30:00.5"},      // twice in the autumn
                {"America/Sao_Paulo", "2018-11-04 00:30:00"},    // the gap at midnight
                {"Australia/Lord_Howe", "2026-10-04 02:15:00"},  // a gap of half an hour
                {"Pacific/Apia", "2011-12-30 12:00:00"},         // a day that was skipped
                {"UTC", "1582-10-10 12:00:00"},                  // between Julian and Gregorian
                {"UTC", "1582-10-04 23:59:59.999999999"},
                {"UTC", "1000-03-01 00:00:00"},                  // after a Julian leap day
                {"UTC", "0000-01-01 00:00:00"},
                {"UTC", "9999-12-31 23:59:59.999999999"},
                {"Asia/Kolkata", "1970-01-01T05:30:00"},
            };
            for (String[] c : cases) {
                TimeZone.setDefault(TimeZone.getTimeZone(c[0]));
                assertTrue(same(c[1]), c[0] + " " + c[1] + " is a value the direct path takes");
            }
        } finally {
            TimeZone.setDefault(before);
        }
    }

    @Test
    void whatJavaTimeWouldRefuseOrAnotherShapeGoesTheGeneralWay() {
        for (String text : new String[] {"2026-02-30 00:00:00", "2025-02-29 00:00:00", "2026-04-31 10:00:00",
                "2026-01-01 24:00:00", "2026-01-01 23:60:00", "2026-01-01 23:59:60", "2026-13-01 00:00:00",
                "2026-00-01 00:00:00", "2026-01-00 00:00:00", "2026-1-01 00:00:00", "2026-01-01 0:00:00",
                "2026-01-01 00:00:00.", "2026-01-01 00:00:00.1234567890", "2026-01-01 00:00:00,5",
                " 2026-01-01 00:00:00", "2026-01-01 00:00:00 ", "2026-01-01  00:00:00", "2026-01-01x00:00:00",
                "+026-01-01 00:00:00", "2026-01-01 00:00:00+02", "2026-01-01 00:00:00Z", "12026-01-01 00:00:00",
                "2026-01-01", "2026-01-01 00:00", "2026-01-01 00:00:0a",
                // A Julian leap day: java.util.Date has it, java.time does not.
                "1000-02-29 00:00:00"}) {
            assertNull(ReadOnlyResultSet.localTimestamp(text), text);
        }
    }

    /**
     * Whether the direct path took the value; when it did, it must be the
     * Timestamp the JDK makes of it, to the nanosecond.
     */
    private static boolean same(String text) {
        Timestamp direct = ReadOnlyResultSet.localTimestamp(text);
        if (direct == null) {
            return false;
        }
        Timestamp expected = Timestamp.valueOf(text.replace('T', ' '));
        assertNotNull(expected, text);
        assertEquals(expected.getTime(), direct.getTime(), text);
        assertEquals(expected.getNanos(), direct.getNanos(), text);
        assertEquals(expected, direct, text);
        return true;
    }

    private static String generated(SplittableRandom random) {
        int year = random.nextInt(4) == 0 ? random.nextInt(10_000) : 1900 + random.nextInt(200);
        int month = 1 + random.nextInt(12);
        int day = 1 + random.nextInt(31);                   // the 31st of April is the general way's
        String text = String.format(Locale.ROOT, "%04d-%02d-%02d%s%02d:%02d:%02d", year, month, day,
                random.nextBoolean() ? " " : "T", random.nextInt(24), random.nextInt(60), random.nextInt(60));
        int precision = random.nextInt(10);
        if (precision > 0) {
            StringBuilder fraction = new StringBuilder(".");
            for (int i = 0; i < precision; i++) {
                fraction.append((char) ('0' + random.nextInt(10)));
            }
            text += fraction;
        }
        return text;
    }

    /** Values at the edges of a day, a month, a year and of the zones' transitions. */
    private static String edge(SplittableRandom random) {
        String[] days = {"2026-03-29", "2026-10-25", "2026-03-08", "2026-11-01", "2018-11-04", "2019-02-16",
            "2026-04-05", "2026-10-04", "2011-12-29", "2011-12-31", "1582-10-15", "1582-10-04", "2024-02-29",
            "1900-02-28", "2000-02-29", "1970-01-01", "1969-12-31"};
        String day = days[random.nextInt(days.length)];
        return String.format(Locale.ROOT, "%s %02d:%02d:%02d.%d", day, random.nextInt(24), random.nextBoolean() ? 0 : 30,
                random.nextInt(60), random.nextInt(1000));
    }
}
