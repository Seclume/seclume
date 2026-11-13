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

    /**
     * An integer from the raw bytes, according to the type.
     * @throws NumberFormatException if a textual value is not an integer;
     *         JDBC getters translate this to a SQL exception
     */
    public static long toLong(ValueCells row, int column) throws NumberFormatException {
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

    /**
     * The floating-point number from the raw bytes.
     * @throws NumberFormatException if a textual value is not a number;
     *         JDBC getters translate this to a SQL exception
     */
    public static double toDouble(ValueCells row, int column) throws NumberFormatException {
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
            case MyTypes.DATETIME, MyTypes.TIMESTAMP ->
                    timestamp(row, at, length, field.decimals());
            case MyTypes.TIME -> time(row, at, length, field.decimals());
            default -> row.textAt(at, length);
        };
    }

    /**
     * The fraction to as many digits as the column declares, as the text
     * protocol writes it: a {@code timestamp(3)} is {@code .123}, not
     * {@code .123000}. The wire always carries microseconds.
     */
    static void fraction(StringBuilder text, long micros, int decimals) {
        int from = text.length();
        text.append('.');
        digits(text, micros, 6);
        if (decimals >= 1 && decimals < 6) {
            text.setLength(from + 1 + decimals);
        }
    }

    /**
     * {@code value} in decimal, zeros in front up to {@code width} - what
     * {@code %0<width>d} writes for a value that is not negative, without a
     * Formatter: three of those per timestamp were most of the time a
     * prepared query spent reading one.
     */
    static void digits(StringBuilder text, long value, int width) {
        int length = 1;
        for (long rest = value; rest >= 10; rest /= 10) {
            length++;
        }
        for (int i = length; i < width; i++) {
            text.append('0');
        }
        text.append(value);
    }

    /** {@code YYYY-MM-DD}; zero bytes mean the zero date. */
    private static String date(ValueCells row, int at, int length) {
        if (length == 0) {
            return "0000-00-00";
        }
        StringBuilder text = new StringBuilder(10);
        date(text, row, at);
        return text.toString();
    }

    private static void date(StringBuilder text, ValueCells row, int at) {
        dateText(text, (int) row.unsignedAt(at, 2), row.byteAt(at + 2) & 0xff,
                row.byteAt(at + 3) & 0xff);
    }

    static void dateText(StringBuilder text, int year, int month, int day) {
        digits(text, year, 4);
        text.append('-');
        digits(text, month, 2);
        text.append('-');
        digits(text, day, 2);
    }

    /** {@code YYYY-MM-DD HH:MM:SS[.ffffff]}. */
    private static String timestamp(ValueCells row, int at, int length, int decimals) {
        if (length == 0) {
            return "0000-00-00 00:00:00";
        }
        StringBuilder text = new StringBuilder(26);
        date(text, row, at);
        if (length <= 4) {
            return text.append(" 00:00:00").toString();
        }
        text.append(' ');
        clock(text, row.byteAt(at + 4) & 0xff, row.byteAt(at + 5) & 0xff,
                row.byteAt(at + 6) & 0xff);
        if (length >= 11) {
            fraction(text, row.unsignedAt(at + 7, 4), decimals);
        }
        return text.toString();
    }

    static void clock(StringBuilder text, long hours, int minute, int second) {
        digits(text, hours, 2);
        text.append(':');
        digits(text, minute, 2);
        text.append(':');
        digits(text, second, 2);
    }

    /**
     * {@code [-]HH:MM:SS[.ffffff]} - and the hours can go past 24, because in
     * MySQL {@code TIME} is a span of time, not a time of day.
     */
    private static String time(ValueCells row, int at, int length, int decimals) {
        if (length == 0) {
            return "00:00:00";
        }
        boolean negative = row.byteAt(at) != 0;
        long days = row.unsignedAt(at + 1, 4);
        int hour = row.byteAt(at + 5) & 0xff;
        StringBuilder text = new StringBuilder(18);
        if (negative) {
            text.append('-');
        }
        clock(text, days * 24 + hour, row.byteAt(at + 6) & 0xff, row.byteAt(at + 7) & 0xff);
        if (length >= 12) {
            fraction(text, row.unsignedAt(at + 8, 4), decimals);
        }
        return text.toString();
    }
}
