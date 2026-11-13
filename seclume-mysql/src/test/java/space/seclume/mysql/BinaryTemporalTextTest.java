package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.SplittableRandom;

import org.junit.jupiter.api.Test;

/**
 * The text of a binary date, time or timestamp is built by hand now; it must
 * be exactly what the {@code String.format} patterns it replaces wrote, for
 * every value the wire can carry - not only for valid dates.
 */
class BinaryTemporalTextTest {

    private static String date(int year, int month, int day) {
        StringBuilder text = new StringBuilder();
        BinaryValues.dateText(text, year, month, day);
        return text.toString();
    }

    private static String clock(long hours, int minute, int second) {
        StringBuilder text = new StringBuilder();
        BinaryValues.clock(text, hours, minute, second);
        return text.toString();
    }

    private static String fraction(long micros, int decimals) {
        StringBuilder text = new StringBuilder();
        BinaryValues.fraction(text, micros, decimals);
        return text.toString();
    }

    /** What the old code wrote. */
    private static String formattedFraction(long micros, int decimals) {
        String six = String.format(".%06d", micros);
        return decimals >= 1 && decimals < 6 ? six.substring(0, 1 + decimals) : six;
    }

    @Test
    void theEdgesOfEveryField() {
        int[] years = {0, 1, 9, 10, 99, 100, 999, 1000, 1970, 2026, 9999, 10000, 65535};
        int[] bytes = {0, 1, 9, 10, 12, 31, 59, 99, 100, 255};
        for (int year : years) {
            for (int month : bytes) {
                for (int day : bytes) {
                    assertEquals(String.format("%04d-%02d-%02d", year, month, day),
                            date(year, month, day));
                }
            }
        }
        long[] hours = {0, 1, 9, 10, 23, 24, 99, 100, 838, 999, 1000, 4294967295L * 24 + 255};
        for (long hour : hours) {
            for (int minute : bytes) {
                for (int second : bytes) {
                    assertEquals(String.format("%02d:%02d:%02d", hour, minute, second),
                            clock(hour, minute, second));
                }
            }
        }
        long[] micros = {0, 1, 9, 10, 99999, 100000, 123456, 999999, 1000000, 4294967295L};
        for (long micro : micros) {
            for (int decimals = 0; decimals <= 7; decimals++) {
                assertEquals(formattedFraction(micro, decimals), fraction(micro, decimals),
                        micro + " to " + decimals);
            }
        }
    }

    @Test
    void randomValuesOfTheWire() {
        SplittableRandom random = new SplittableRandom(13);
        for (int i = 0; i < 200_000; i++) {
            int year = random.nextInt(65536);
            int month = random.nextInt(256);
            int day = random.nextInt(256);
            assertEquals(String.format("%04d-%02d-%02d", year, month, day), date(year, month, day));
            long hour = random.nextLong(4294967296L) * 24 + random.nextInt(256);
            int minute = random.nextInt(256);
            int second = random.nextInt(256);
            assertEquals(String.format("%02d:%02d:%02d", hour, minute, second),
                    clock(hour, minute, second));
            long micro = random.nextLong(4294967296L);
            int decimals = random.nextInt(8);
            assertEquals(formattedFraction(micro, decimals), fraction(micro, decimals));
        }
    }

    /** One binary cell, as the row decoder sees it. */
    private static String text(int type, int decimals, int... wire) {
        byte[] bytes = new byte[wire.length];
        for (int i = 0; i < wire.length; i++) {
            bytes[i] = (byte) wire[i];
        }
        MySession.Field field = new MySession.Field("d", "t", "c", "c", 63, 26, type, 0, decimals);
        ValueCells cell = new ValueCells() {
            @Override public List<MySession.Field> fields() { return List.of(field); }
            @Override public int offset(int column) { return 0; }
            @Override public int length(int column) { return bytes.length; }
            @Override public byte byteAt(int at) { return bytes[at]; }
            @Override public long unsignedAt(int at, int length) {
                long value = 0;
                for (int i = length - 1; i >= 0; i--) {
                    value = (value << 8) | (bytes[at + i] & 0xff);
                }
                return value;
            }
            @Override public long decimalAt(int at, int length) { throw new UnsupportedOperationException(); }
            @Override public String textAt(int at, int length) { throw new UnsupportedOperationException(); }
        };
        return BinaryValues.toText(cell, 0);
    }

    /** Every length the server sends a temporal value in, read through the decoder. */
    @Test
    void everyWireLengthOfATemporalValue() {
        // 2026-11-13, 09:05:07, 123456 microseconds; 0x07ea = 2026, 0x01e240 = 123456
        assertEquals("0000-00-00", text(MyTypes.DATE, 0));
        assertEquals("2026-11-13", text(MyTypes.DATE, 0, 0xea, 0x07, 11, 13));
        assertEquals("0000-00-00 00:00:00", text(MyTypes.DATETIME, 0));
        assertEquals("2026-11-13 00:00:00", text(MyTypes.DATETIME, 0, 0xea, 0x07, 11, 13));
        assertEquals("2026-11-13 09:05:07", text(MyTypes.TIMESTAMP, 0, 0xea, 0x07, 11, 13, 9, 5, 7));
        assertEquals("2026-11-13 09:05:07.123456",
                text(MyTypes.DATETIME, 6, 0xea, 0x07, 11, 13, 9, 5, 7, 0x40, 0xe2, 0x01, 0));
        assertEquals("2026-11-13 09:05:07.123",
                text(MyTypes.DATETIME, 3, 0xea, 0x07, 11, 13, 9, 5, 7, 0x40, 0xe2, 0x01, 0));
        assertEquals("2026-11-13 09:05:07.000001",
                text(MyTypes.DATETIME, 6, 0xea, 0x07, 11, 13, 9, 5, 7, 1, 0, 0, 0));
        assertEquals("00:00:00", text(MyTypes.TIME, 0));
        assertEquals("09:05:07", text(MyTypes.TIME, 0, 0, 0, 0, 0, 0, 9, 5, 7));
        // 34 days and 22 hours: 838 hours, the largest a TIME holds.
        assertEquals("-838:59:59", text(MyTypes.TIME, 0, 1, 34, 0, 0, 0, 22, 59, 59));
        assertEquals("-838:59:59.000000", text(MyTypes.TIME, 6, 1, 34, 0, 0, 0, 22, 59, 59, 0, 0, 0, 0));
        assertEquals("09:05:07.12", text(MyTypes.TIME, 2, 0, 0, 0, 0, 0, 9, 5, 7, 0x40, 0xe2, 0x01, 0));
    }
}
