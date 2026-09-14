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
 * time zone two more for the offset. Those two are read but not applied: what
 * comes out is the local time the server sent, which is what every other
 * client shows as well.
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
        int century = byteAt(in, at) - YEAR_BIAS;
        int year = byteAt(in, at + 1) - YEAR_BIAS;
        StringBuilder text = new StringBuilder(29); // seclume-allow: a date on its way to the caller, not a secret
        pad(text, century * YEAR_BIAS + year, 4);
        text.append('-');
        pad(text, byteAt(in, at + 2), 2);
        text.append('-');
        pad(text, byteAt(in, at + 3), 2);
        text.append(' ');
        pad(text, byteAt(in, at + 4) - TIME_BIAS, 2);
        text.append(':');
        pad(text, byteAt(in, at + 5) - TIME_BIAS, 2);
        text.append(':');
        pad(text, byteAt(in, at + 6) - TIME_BIAS, 2);

        if (length >= DATE_LENGTH + 4) {
            long nanos = 0;
            for (int i = 0; i < 4; i++) {
                nanos = (nanos << 8) | byteAt(in, at + DATE_LENGTH + i);
            }
            if (nanos > 0) {
                text.append('.');
                pad(text, nanos, NANO_DIGITS);
                while (text.charAt(text.length() - 1) == '0') {
                    text.setLength(text.length() - 1);
                }
            }
        }
        return text.toString();
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
