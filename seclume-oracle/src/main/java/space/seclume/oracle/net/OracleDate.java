package space.seclume.oracle.net;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Oracle's {@code DATE} and {@code TIMESTAMP} on the wire.
 *
 * <p>Seven bytes, and none of them is a plain number: century and year are
 * both shifted by 100 and hour, minute and second by one. The reason is the
 * same as with {@code NUMBER} - no byte may be zero, and the bytes have to
 * sort in the order of the values.
 *
 * <p>A {@code TIMESTAMP} appends four bytes of nanoseconds, and one with a
 * time zone two more for the zone. With a zone the seven bytes are UTC, and
 * the zone is either an offset or the number of a region in Oracle's time
 * zone file - see {@link #isRegion}.
 *
 * <p>Rendered as ISO text - {@code yyyy-MM-dd HH:mm:ss} - because that is what
 * {@code java.sql.Timestamp.valueOf} takes, and because Oracle's own default
 * format depends on a session setting that a driver should not depend on.
 */
public final class OracleDate {

    /** The bytes of a bare date. */
    public static final int DATE_LENGTH = 7;
    /** Oracle's offset for the century and the year. */
    private static final int YEAR_BIAS = 100;
    /** Hour, minute and second are shifted by this. */
    private static final int TIME_BIAS = 1;
    /** Oracle's offset for the hours of a time zone. */
    private static final int ZONE_HOUR_BIAS = 20;
    /** And for its minutes. */
    private static final int ZONE_MINUTE_BIAS = 60;
    /** Digits of a fraction of a second. */
    private static final int NANO_DIGITS = 9;

    private OracleDate() {
    }

    /** Whether a column carries a point in time in this format. */
    public static boolean isDate(int type) {
        return type == OracleColumn.TYPE_DATE
                || type == OracleColumn.TYPE_TIMESTAMP
                || type == OracleColumn.TYPE_TIMESTAMP_ZONE
                || type == OracleColumn.TYPE_TIMESTAMP_LOCAL;
    }

    /**
     * The value as ISO text.
     *
     * @param length the bytes the column carries - seven for a date, more for
     *               a timestamp
     */
    public static String toText(MemorySegment in, long at, int length) {
        if (length < DATE_LENGTH) {
            return "";
        }
        boolean zoned = length >= DATE_LENGTH + 6 && !isRegion(in, at, length);
        java.time.LocalDateTime value = fields(in, at, length);
        if (zoned) {
            // The fields are UTC; the text names the local time beside its
            // offset, or it names another point in time.
            value = value.plusMinutes(zoneMinutes(in, at));
        }
        StringBuilder text = new StringBuilder(29); // seclume-allow: a date on its way to the caller, not a secret
        pad(text, value.getYear(), 4);
        text.append('-');
        pad(text, value.getMonthValue(), 2);
        text.append('-');
        pad(text, value.getDayOfMonth(), 2);
        text.append(' ');
        pad(text, value.getHour(), 2);
        text.append(':');
        pad(text, value.getMinute(), 2);
        text.append(':');
        pad(text, value.getSecond(), 2);

        if (length >= DATE_LENGTH + 4) {
            long nanos = value.getNano();
            if (nanos > 0) {
                text.append('.');
                pad(text, nanos, NANO_DIGITS);
                while (text.charAt(text.length() - 1) == '0') {
                    text.setLength(text.length() - 1);
                }
            }
        }
        if (length >= DATE_LENGTH + 6 && !zoned) {
            text.append('Z');                   // a region: the UTC fields, said so
        } else if (zoned) {
            // A TIMESTAMP WITH TIME ZONE carries two more bytes: the hour
            // shifted by 20 and the minute by 60. Dropping them, which this
            // did, turns a value that names a point in time into bare
            // fields - and whoever reads it then reads them in the machine's
            // own zone. An Instant written as 09:29 UTC came back as 07:29
            // UTC on a machine two hours ahead, with nothing to show for it.
            int hours = byteAt(in, at + DATE_LENGTH + 4) - ZONE_HOUR_BIAS;
            int minutes = byteAt(in, at + DATE_LENGTH + 5) - ZONE_MINUTE_BIAS;
            text.append(hours < 0 || minutes < 0 ? '-' : '+');
            pad(text, Math.abs(hours), 2);
            text.append(':');
            pad(text, Math.abs(minutes), 2);
        }
        return text.toString();
    }

    /**
     * The fields as they are on the wire.
     *
     * <p>For a {@code TIMESTAMP WITH TIME ZONE} those are <b>UTC</b>, with the
     * zone beside them; for {@code WITH LOCAL TIME ZONE} they are in the
     * database's zone. Neither is the local time the value names - see
     * {@link #zoneMinutes} and {@link #regionId}.
     */
    public static java.time.LocalDateTime fields(MemorySegment in, long at, int length) {
        int nanos = 0;
        if (length >= DATE_LENGTH + 4) {
            for (int i = 0; i < 4; i++) {
                nanos = (nanos << 8) | byteAt(in, at + DATE_LENGTH + i);
            }
        }
        return java.time.LocalDateTime.of(
                (byteAt(in, at) - YEAR_BIAS) * YEAR_BIAS + byteAt(in, at + 1) - YEAR_BIAS,
                byteAt(in, at + 2), byteAt(in, at + 3),
                byteAt(in, at + 4) - TIME_BIAS, byteAt(in, at + 5) - TIME_BIAS,
                byteAt(in, at + 6) - TIME_BIAS, nanos);
    }

    /**
     * Whether the zone is a region - {@code Europe/Vienna} - rather than an
     * offset: the top bit of the zone's first byte. The two bytes then hold
     * the region's number in Oracle's time zone file, not hours and minutes;
     * read as an offset they made "+113:156".
     */
    public static boolean isRegion(MemorySegment in, long at, int length) {
        return length >= DATE_LENGTH + 6 && (byteAt(in, at + DATE_LENGTH + 4) & 0x80) != 0;
    }

    /** The region's number: seven bits of the first zone byte, six of the second. */
    public static int regionId(MemorySegment in, long at) {
        return ((byteAt(in, at + DATE_LENGTH + 4) & 0x7f) << 6)
                | ((byteAt(in, at + DATE_LENGTH + 5) & 0xfc) >> 2);
    }

    /** An offset zone in minutes east of UTC. */
    public static int zoneMinutes(MemorySegment in, long at) {
        return (byteAt(in, at + DATE_LENGTH + 4) - ZONE_HOUR_BIAS) * 60
                + byteAt(in, at + DATE_LENGTH + 5) - ZONE_MINUTE_BIAS;
    }

    /** The bias on the four-byte fields of an interval: 2^31 is zero. */
    private static final long INTERVAL_BIAS = 0x8000_0000L;
    /** And on its one-byte fields. */
    private static final int INTERVAL_FIELD_BIAS = 60;

    /**
     * {@code INTERVAL YEAR TO MONTH} as ojdbc writes it: {@code 1-2},
     * {@code -5-11}. Four bytes of years, one of months, each biased so the
     * bytes sort as the values do.
     */
    public static String intervalYearToMonth(MemorySegment in, long at) {
        long years = unsigned(in, at, 4) - INTERVAL_BIAS;
        int months = byteAt(in, at + 4) - INTERVAL_FIELD_BIAS;
        // One sign for the whole: -0-3 is minus three months.
        return (years < 0 || months < 0 ? "-" : "") + Math.abs(years) + "-" + Math.abs(months);
    }

    /**
     * {@code INTERVAL DAY TO SECOND} as ojdbc writes it:
     * {@code 1 2:3:4.5}, unpadded, the fraction without trailing zeros.
     */
    public static String intervalDayToSecond(MemorySegment in, long at) {
        long days = unsigned(in, at, 4) - INTERVAL_BIAS;
        int hours = byteAt(in, at + 4) - INTERVAL_FIELD_BIAS;
        int minutes = byteAt(in, at + 5) - INTERVAL_FIELD_BIAS;
        int seconds = byteAt(in, at + 6) - INTERVAL_FIELD_BIAS;
        long nanos = Math.abs(unsigned(in, at + 7, 4) - INTERVAL_BIAS);
        String fraction = String.format("%09d", nanos).replaceAll("0+$", "");
        boolean negative = days < 0 || hours < 0 || minutes < 0 || seconds < 0
                || unsigned(in, at + 7, 4) < INTERVAL_BIAS;
        return (negative ? "-" : "") + Math.abs(days) + " " + Math.abs(hours) + ":"
                + Math.abs(minutes) + ":" + Math.abs(seconds) + "."
                + (fraction.isEmpty() ? "0" : fraction);
    }

    private static long unsigned(MemorySegment in, long at, int bytes) {
        long value = 0;
        for (int i = 0; i < bytes; i++) {
            value = (value << 8) | byteAt(in, at + i);
        }
        return value;
    }

    private static void pad(StringBuilder text, long value, int digits) {
        String number = Long.toString(Math.abs(value));
        for (int i = number.length(); i < digits; i++) {
            text.append('0');
        }
        text.append(number);
    }

    private static int byteAt(MemorySegment in, long at) {
        return in.get(ValueLayout.JAVA_BYTE, at) & 0xff;
    }
}
