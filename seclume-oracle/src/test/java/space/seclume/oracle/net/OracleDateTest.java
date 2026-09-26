package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.internal.WireBuffer;

/**
 * Oracle's seven bytes for a point in time.
 *
 * <p>The first vector is not invented: {@code 78 7e 09 08} is what a real
 * server sent for the eighth of September 2026 - century 0x78 is 120, so 20,
 * and year 0x7e is 126, so 26. Everything else follows the same rule, and the
 * round trip below checks the writer against the reader over the whole
 * range of values.
 */
class OracleDateTest {

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource({
        "787e0908010101,      2026-09-08 00:00:00",
        "787e0102040506,      2026-01-02 03:04:05",
        "76c70c1f010101,      1899-12-31 00:00:00",
        "78640117012c3b,      2000-01-23 00:43:58",
    })
    void readsTheSevenBytes(String hex, String expected) {
        String bytes = hex;
        try (WireBuffer in = new WireBuffer(32)) {
            for (int i = 0; i + 1 < bytes.length(); i += 2) {
                in.putByte((byte) Integer.parseInt(bytes.substring(i, i + 2), 16));
            }
            assertEquals(expected, OracleDate.toText(in.segment(), 0, bytes.length() / 2));
        }
    }

    /** A timestamp appends four bytes of nanoseconds. */
    @Test
    void readsTheFractionOfATimestamp() {
        try (WireBuffer in = new WireBuffer(32)) {
            for (int value : new int[] {0x78, 0x7e, 0x01, 0x02, 0x04, 0x05, 0x06,
                                        0x07, 0x5b, 0xca, 0x00}) {
                in.putByte((byte) value);
            }
            // 0x075bca00 is 123456000 nanoseconds, and the trailing zeroes
            // of the nine digits are cut.
            assertEquals("2026-01-02 03:04:05.123456", OracleDate.toText(in.segment(), 0, 11));
        }
    }

    /**
     * What the driver writes has to be what the driver reads - the two are
     * separate implementations of the same shifted bytes.
     *
     * <p>A {@code LocalDateTime} goes as a TIMESTAMP - eleven bytes when it
     * has a fraction of a second, seven when it has none, as ojdbc sends it.
     * The four at the end are the fraction, and binding a point in time as a
     * DATE type threw it away silently: the type stays TIMESTAMP either way.
     * The last two values here have one, so that a driver that went back to
     * seven bytes would be caught by the value and not only by the length.
     */
    @ParameterizedTest
    @CsvSource({"2026-09-08T00:00", "1899-12-31T23:59:59", "2000-02-29T12:00:01",
                "1970-01-01T00:00", "2099-12-31T23:59:59",
                "2026-09-20T11:29:16.153456789", "2026-09-20T11:29:16.000000001"})
    void readsBackWhatItWrote(String value) throws Exception {
        LocalDateTime stamp = LocalDateTime.parse(value);
        TtcBinds binds = new TtcBinds();
        binds.set(1, stamp);
        try (WireBuffer out = new WireBuffer(32)) {
            binds.putValues(out);
            // Behind the ROW_DATA byte comes the length, and then the bytes.
            int length = out.getByte(1) & 0xff;
            assertEquals(stamp.getNano() == 0 ? OracleDate.DATE_LENGTH
                    : OracleDate.DATE_LENGTH + 4, length);
            String expected = stamp.toString().replace('T', ' ')
                    + (stamp.getSecond() == 0 && stamp.getNano() == 0 ? ":00" : "");
            assertEquals(expected, OracleDate.toText(out.segment(), 2, length));
        }
    }
}
