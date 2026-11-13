package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Date;
import java.sql.Time;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.SplittableRandom;
import java.util.TimeZone;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.WireBuffer;

/**
 * A datetime2, datetime or smalldatetime read as fields must be the value its
 * text was: Timestamp, Date and Time.valueOf of what {@link TdsValues#asText}
 * writes for the same bytes - the path getTimestamp, getDate, getTime and
 * getObject took before.
 */
@Isolated("sets the JVM's default time zone")
class TdsTemporalFieldsTest {

    private static final String[] ZONES = {"UTC", "Europe/Vienna", "America/Sao_Paulo",
        "Australia/Lord_Howe", "Pacific/Apia"};

    @Test
    void theFieldsAreTheValueTheTextWas() {
        TimeZone before = TimeZone.getDefault();
        try (WireBuffer buffer = new WireBuffer(32)) {
            for (String zone : ZONES) {
                TimeZone.setDefault(TimeZone.getTimeZone(zone));
                SplittableRandom random = new SplittableRandom(zone.hashCode());
                int taken = 0;
                for (int round = 0; round < 60_000; round++) {
                    int kind = random.nextInt(3);
                    buffer.clear();
                    int type;
                    int scale = 0;
                    if (kind == 0) {
                        type = TdsTypes.DATETIME2N;
                        scale = random.nextInt(8);
                        int timeBytes = scale <= 2 ? 3 : scale <= 4 ? 4 : 5;
                        long perDay = 86_400L * pow10(scale);
                        long ticks = random.nextInt(20) == 0 ? perDay + random.nextLong(perDay)
                                : random.nextLong(perDay);
                        long days = random.nextInt(20) == 0 ? random.nextLong(1 << 24) : random.nextLong(3_652_059);
                        little(buffer, ticks, timeBytes);
                        little(buffer, days, 3);
                    } else if (kind == 1) {
                        type = random.nextBoolean() ? TdsTypes.DATETIME : TdsTypes.DATETIMN;
                        long days = random.nextInt(20) == 0 ? random.nextInt() : -53_690 + random.nextInt(2_958_463 + 53_690);
                        long ticks = random.nextInt(20) == 0 ? random.nextLong(1L << 32) : random.nextLong(25_920_000);
                        little(buffer, days, 4);
                        little(buffer, ticks, 4);
                    } else {
                        type = random.nextBoolean() ? TdsTypes.DATETIM4 : TdsTypes.DATETIMN;
                        little(buffer, random.nextInt(65_536), 2);
                        little(buffer, random.nextInt(20) == 0 ? random.nextInt(65_536) : random.nextInt(1_440), 2);
                    }
                    int length = buffer.position();
                    LocalDateTime fields = TdsValues.asLocalDateTime(buffer, type, 0, length, scale);
                    if (fields == null) {
                        continue;
                    }
                    taken++;
                    String text = TdsValues.asText(buffer, type, 0, length, scale);
                    Timestamp expected = Timestamp.valueOf(text);
                    Timestamp direct = Timestamp.valueOf(fields);
                    assertEquals(expected.getTime(), direct.getTime(), zone + " " + text);
                    assertEquals(expected.getNanos(), direct.getNanos(), zone + " " + text);
                    assertEquals(Date.valueOf(text.substring(0, 10)), Date.valueOf(fields.toLocalDate()), text);
                    assertEquals(Time.valueOf(text.substring(11, 19)), Time.valueOf(fields.toLocalTime()), text);
                }
                assertTrue(taken > 45_000, zone + ": " + taken + " values were read as fields");
            }
        } finally {
            TimeZone.setDefault(before);
        }
    }

    @Test
    void whatTheTextHasToSayGoesTheGeneralWay() {
        try (WireBuffer buffer = new WireBuffer(32)) {
            // A datetime2 past 23:59:59.
            little(buffer, 86_400L * 100, 3);
            little(buffer, 738_000, 3);
            assertNull(TdsValues.asLocalDateTime(buffer, TdsTypes.DATETIME2N, 0, 6, 2));
            // A datetime2 in year 10000 and later.
            buffer.clear();
            little(buffer, 0, 3);
            little(buffer, 3_652_059, 3);
            assertNull(TdsValues.asLocalDateTime(buffer, TdsTypes.DATETIME2N, 0, 6, 2));
            // A scale the format does not have, a length it does not have.
            assertNull(TdsValues.asLocalDateTime(buffer, TdsTypes.DATETIME2N, 0, 6, 8));
            assertNull(TdsValues.asLocalDateTime(buffer, TdsTypes.DATETIME, 0, 6, 0));
            // A datetime before year 0.
            buffer.clear();
            little(buffer, Integer.MIN_VALUE, 4);
            little(buffer, 0, 4);
            assertNull(TdsValues.asLocalDateTime(buffer, TdsTypes.DATETIME, 0, 8, 0));
            // Types that are not these three.
            assertNull(TdsValues.asLocalDateTime(buffer, TdsTypes.DATEN, 0, 3, 0));
            assertNull(TdsValues.asLocalDateTime(buffer, TdsTypes.DATETIMEOFFSETN, 0, 8, 0));
        }
    }

    private static void little(WireBuffer buffer, long value, int bytes) {
        for (int i = 0; i < bytes; i++) {
            buffer.putByte((byte) (value >>> (8 * i)));
        }
    }

    private static long pow10(int exponent) {
        long value = 1;
        for (int i = 0; i < exponent; i++) {
            value *= 10;
        }
        return value;
    }
}
