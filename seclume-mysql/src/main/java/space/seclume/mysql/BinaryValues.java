package space.seclume.mysql;

/**
 * The reading of the binary values from {@code COM_STMT_EXECUTE}.
 *
 * <p>In the binary protocol a number arrives as a number - four bytes
 * little-endian instead of ten digits. That is faster and more precise, but it
 * also means: without the column type the bytes are meaningless. This class is
 * the one place where type and bytes turn into a value.
 *
 * <p>The time types are the unpleasant part. MySQL sends them in a structure of
 * variable length: zero bytes means "zero value" (not NULL - that one is in the
 * bitmask), four bytes are a date, seven date and time, eleven add
 * microseconds. Whoever does not check the length reads the next column along
 * with it.
 */
public final class BinaryValues {

    private BinaryValues() {
    }

    /** An integer from the raw bytes, according to the type. */
    public static long toLong(ValueCells row, int column) {
        MySession.Field field = row.fields().get(column);
        int at = row.offset(column);
        int length = row.length(column);
        boolean unsigned = field.unsigned();
        return switch (field.type()) {
            case MyTypes.TINY -> unsigned ? row.unsignedAt(at, 1) : row.byteAt(at);
            case MyTypes.SHORT, MyTypes.YEAR -> {
                long value = row.unsignedAt(at, 2);
                yield unsigned ? value : (short) value;
            }
            case MyTypes.LONG, MyTypes.INT24 -> {
                long value = row.unsignedAt(at, 4);
                yield unsigned ? value : (int) value;
            }
            case MyTypes.LONGLONG -> row.unsignedAt(at, 8);
            case MyTypes.BIT -> bits(row, at, length);
            case MyTypes.FLOAT -> (long) Float.intBitsToFloat((int) row.unsignedAt(at, 4));
            case MyTypes.DOUBLE -> (long) Double.longBitsToDouble(row.unsignedAt(at, 8));
            default -> {
                // Everything else arrives as text, in the binary protocol
                // too - decimal, bit, blob and the strings.
                String text = row.textAt(at, length);
                yield Long.parseLong(text.trim());
            }
        };
    }

    /**
     * A {@code bit} column: the bits themselves, most significant byte
     * first.
     *
     * <p>Not text, which is what everything else that is not a fixed-width
     * number arrives as - a {@code bit(1)} holding true is the single byte
     * 0x01, and reading that as a digit yields no number at all. Hibernate
     * maps a Java {@code boolean} to {@code bit(1)} on MySQL, so this is the
     * ordinary case: the error was "For input string" on every entity with a
     * boolean in it.
     */
    private static long bits(ValueCells row, int at, int length) {
        long value = 0;
        for (int i = 0; i < length; i++) {
            value = (value << 8) | (row.byteAt(at + i) & 0xff);
        }
        return value;
    }

    /** The floating-point number from the raw bytes. */
    public static double toDouble(ValueCells row, int column) {
        MySession.Field field = row.fields().get(column);
        int at = row.offset(column);
        return switch (field.type()) {
            case MyTypes.FLOAT -> Float.intBitsToFloat((int) row.unsignedAt(at, 4));
            case MyTypes.DOUBLE -> Double.longBitsToDouble(row.unsignedAt(at, 8));
            case MyTypes.TINY, MyTypes.SHORT, MyTypes.YEAR, MyTypes.LONG,
                 MyTypes.INT24, MyTypes.LONGLONG, MyTypes.BIT -> toLong(row, column);
            default -> Double.parseDouble(row.textAt(at, row.length(column)).trim());
        };
    }

    /** The text form of a binary value - the way the text protocol sends it. */
    public static String toText(ValueCells row, int column) {
        MySession.Field field = row.fields().get(column);
        int at = row.offset(column);
        int length = row.length(column);
        return switch (field.type()) {
            case MyTypes.TINY, MyTypes.SHORT, MyTypes.YEAR, MyTypes.LONG,
                 MyTypes.INT24, MyTypes.BIT -> Long.toString(toLong(row, column));
            case MyTypes.LONGLONG -> {
                long value = row.unsignedAt(at, 8);
                yield field.unsigned() ? Long.toUnsignedString(value) : Long.toString(value);
            }
            case MyTypes.FLOAT -> Float.toString(Float.intBitsToFloat((int) row.unsignedAt(at, 4)));
            case MyTypes.DOUBLE ->
                    Double.toString(Double.longBitsToDouble(row.unsignedAt(at, 8)));
            case MyTypes.DATE, MyTypes.NEWDATE -> date(row, at, length);
            case MyTypes.DATETIME, MyTypes.TIMESTAMP -> timestamp(row, at, length);
            case MyTypes.TIME -> time(row, at, length);
            default -> row.textAt(at, length);
        };
    }

    /** {@code YYYY-MM-DD}; zero bytes mean the zero date. */
    private static String date(ValueCells row, int at, int length) {
        if (length == 0) {
            return "0000-00-00";
        }
        int year = (int) row.unsignedAt(at, 2);
        int month = row.byteAt(at + 2) & 0xff;
        int day = row.byteAt(at + 3) & 0xff;
        return String.format("%04d-%02d-%02d", year, month, day);
    }

    /** {@code YYYY-MM-DD HH:MM:SS[.ffffff]}. */
    private static String timestamp(ValueCells row, int at, int length) {
        if (length == 0) {
            return "0000-00-00 00:00:00";
        }
        String day = date(row, at, length);
        if (length <= 4) {
            return day + " 00:00:00";
        }
        int hour = row.byteAt(at + 4) & 0xff;
        int minute = row.byteAt(at + 5) & 0xff;
        int second = row.byteAt(at + 6) & 0xff;
        String base = String.format("%s %02d:%02d:%02d", day, hour, minute, second);
        if (length < 11) {
            return base;
        }
        long micros = row.unsignedAt(at + 7, 4);
        return base + String.format(".%06d", micros);
    }

    /**
     * {@code [-]HH:MM:SS[.ffffff]} - and the hours can go past 24, because in
     * MySQL {@code TIME} is a span of time, not a time of day.
     */
    private static String time(ValueCells row, int at, int length) {
        if (length == 0) {
            return "00:00:00";
        }
        boolean negative = row.byteAt(at) != 0;
        long days = row.unsignedAt(at + 1, 4);
        int hour = row.byteAt(at + 5) & 0xff;
        int minute = row.byteAt(at + 6) & 0xff;
        int second = row.byteAt(at + 7) & 0xff;
        long hours = days * 24 + hour;
        String base = String.format("%s%02d:%02d:%02d", negative ? "-" : "", hours, minute, second);
        if (length < 12) {
            return base;
        }
        long micros = row.unsignedAt(at + 8, 4);
        return base + String.format(".%06d", micros);
    }
}
