package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.SplittableRandom;

import org.junit.jupiter.api.Test;

/**
 * The arithmetic path for a timestamp with its offset, held against the
 * java.time one it replaces on the hot path.
 */
class ZonedTimestampTest {

    @Test
    void everySpellingNamesTheSameInstantAsJavaTime() {
        SplittableRandom random = new SplittableRandom(20260924);
        for (int i = 0; i < 200_000; i++) {
            long second = random.nextLong(-62_135_596_800L, 253_402_300_799L); // 0001..9999
            int nanos = random.nextInt(4) == 0 ? 0 : random.nextInt(1_000_000_000);
            int offsetMinutes = (random.nextInt(-18 * 4, 18 * 4 + 1)) * 15;
            OffsetDateTime value = Instant.ofEpochSecond(second, nanos)
                    .atOffset(ZoneOffset.ofTotalSeconds(offsetMinutes * 60));
            if (value.getYear() < 1 || value.getYear() > 9999) {
                continue;
            }
            for (String text : spellings(value)) {
                Timestamp fast = ReadOnlyResultSet.zonedTimestamp(text);
                Timestamp expected = Timestamp.from(value.toInstant());
                assertEquals(expected, fast, text);
                assertEquals(expected.getNanos(), fast.getNanos(), text);
            }
        }
    }

    @Test
    void anythingElseIsLeftToTheGeneralWay() {
        for (String text : new String[] {"2024-02-29 13:14:15", "2024-02-29", "13:14:15+02",
                "2024-02-29 13:14:15.5 Europe/Vienna", "2024-02-29 13:14:15+02 BC",
                "0024-02-29 13:14:15+02:00:30", "2024-13-01 00:00:00+00",
                "2024-02-29 13:14:15.1234567891+02", "10000-01-01 00:00:00+00",
                "2024-02-29 13:14:15.5 +2:00"}) {
            assertNull(ReadOnlyResultSet.zonedTimestamp(text), text);
        }
    }

    /** How PostgreSQL, SQL Server and ISO write the same instant. */
    private static String[] spellings(OffsetDateTime value) {
        String local = value.toLocalDateTime().format(
                DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss"));
        String fraction = value.getNano() == 0 ? ""
                : "." + String.format("%09d", value.getNano()).replaceAll("0+$", "");
        int total = value.getOffset().getTotalSeconds() / 60;
        String sign = total < 0 ? "-" : "+";
        String hours = String.format("%02d", Math.abs(total) / 60);
        String minutes = String.format("%02d", Math.abs(total) % 60);
        String pg = sign + hours + (Math.abs(total) % 60 == 0 ? "" : ":" + minutes);
        return new String[] {
            local + fraction + pg,                               // PostgreSQL
            local + fraction + " " + sign + hours + ":" + minutes, // SQL Server
            local.replace(' ', 'T') + fraction + sign + hours + ":" + minutes,
            local + fraction + sign + hours + minutes,
        };
    }
}
