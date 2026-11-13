package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.sql.Date;
import java.sql.Time;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.SplittableRandom;
import java.util.TimeZone;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * An Oracle DATE or TIMESTAMP read as fields must be the value its text was:
 * Timestamp, Date and Time.valueOf of what {@link OracleDate#toText} writes for
 * the same bytes - the path getTimestamp, getDate and getTime took before.
 */
@Isolated("sets the JVM's default time zone")
class OracleDateFieldsTest {

    private static final String[] ZONES = {"UTC", "Europe/Vienna", "America/Sao_Paulo",
        "Australia/Lord_Howe", "Pacific/Apia"};

    @Test
    void theFieldsAreTheValueTheTextWas() {
        TimeZone before = TimeZone.getDefault();
        try {
            for (String zone : ZONES) {
                TimeZone.setDefault(TimeZone.getTimeZone(zone));
                SplittableRandom random = new SplittableRandom(zone.hashCode());
                int taken = 0;
                for (int round = 0; round < 60_000; round++) {
                    boolean timestamp = random.nextBoolean();
                    byte[] bytes = new byte[timestamp ? 11 : 7];
                    int year = random.nextInt(10) == 0 ? -4712 + random.nextInt(14_712) : 1900 + random.nextInt(200);
                    int century = Math.floorDiv(year, 100);
                    bytes[0] = (byte) (century + 100);
                    bytes[1] = (byte) (year - century * 100 + 100);
                    bytes[2] = (byte) (random.nextInt(20) == 0 ? random.nextInt(14) : 1 + random.nextInt(12));
                    bytes[3] = (byte) (random.nextInt(20) == 0 ? random.nextInt(32) : 1 + random.nextInt(28));
                    bytes[4] = (byte) (1 + random.nextInt(24));
                    bytes[5] = (byte) (1 + random.nextInt(60));
                    bytes[6] = (byte) (1 + random.nextInt(60));
                    if (timestamp) {
                        int nanos = random.nextInt(4) == 0 ? random.nextInt(1000) * 1_000_000
                                : random.nextInt(1_000_000_000);
                        for (int i = 0; i < 4; i++) {
                            bytes[7 + i] = (byte) (nanos >>> (8 * (3 - i)));
                        }
                    }
                    MemorySegment in = MemorySegment.ofArray(bytes);
                    LocalDateTime fields = OracleDate.localDateTime(in, 0, bytes.length);
                    if (fields == null) {
                        continue;
                    }
                    taken++;
                    String text = OracleDate.toText(in, 0, bytes.length);
                    Timestamp expected = Timestamp.valueOf(text);
                    Timestamp direct = Timestamp.valueOf(fields);
                    assertEquals(expected.getTime(), direct.getTime(), zone + " " + text);
                    assertEquals(expected.getNanos(), direct.getNanos(), zone + " " + text);
                    assertEquals(Date.valueOf(text.substring(0, 10)), Date.valueOf(fields.toLocalDate()), text);
                    assertEquals(Time.valueOf(text.substring(11, 19)), Time.valueOf(fields.toLocalTime()), text);
                }
                assertTrue(taken > 40_000, zone + ": " + taken + " values were read as fields");
            }
        } finally {
            TimeZone.setDefault(before);
        }
    }

    @Test
    void whatTheTextHasToSayGoesTheGeneralWay() {
        // The 31st of February, month 13, a BC year, and lengths that are not a DATE or a TIMESTAMP.
        assertNull(OracleDate.localDateTime(MemorySegment.ofArray(new byte[] {120, 126, 2, 31, 1, 1, 1}), 0, 7));
        assertNull(OracleDate.localDateTime(MemorySegment.ofArray(new byte[] {120, 126, 13, 1, 1, 1, 1}), 0, 7));
        assertNull(OracleDate.localDateTime(MemorySegment.ofArray(new byte[] {99, 100, 1, 1, 1, 1, 1}), 0, 7));
        assertNull(OracleDate.localDateTime(MemorySegment.ofArray(new byte[] {120, 126, 1, 1, 1, 1, 1, 0, 0}), 0, 9));
        assertNull(OracleDate.localDateTime(MemorySegment.ofArray(new byte[13]), 0, 13));
        assertEquals(LocalDateTime.of(2026, 9, 24, 13, 14, 15, 123_000_000), OracleDate.localDateTime(
                MemorySegment.ofArray(new byte[] {120, 126, 9, 24, 14, 15, 16, 7, 84, (byte) 0xd4, (byte) 0xc0}), 0, 11));
    }
}
