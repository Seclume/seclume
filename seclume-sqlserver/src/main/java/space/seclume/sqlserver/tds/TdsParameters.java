package space.seclume.sqlserver.tds;

import java.math.BigDecimal;
import java.sql.SQLException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;

import space.seclume.internal.WireBuffer;

/**
 * The parameters of a prepared statement, on their way to the wire.
 *
 * <p>SQL Server runs a parameterised statement through {@code sp_executesql},
 * and that call needs the parameters twice: once as a declaration
 * ({@code "@P0 int,@P1 nvarchar(4000)"}) and once as values. Both come from
 * here, from the same table - a mismatch between the two is the classic way to
 * get "Error converting data type" out of a statement that looks right.
 *
 * <p>Values never go into the SQL text. SQL injection is not a danger warded
 * off here; on this path it does not exist.
 *
 * <p>Two decisions worth knowing:
 *
 * <ul>
 *   <li>Text goes over as {@code nvarchar}, always. A {@code varchar} would
 *       have to be encoded in the server's code page, which the client cannot
 *       know for sure - and a wrong code page corrupts text silently.</li>
 *   <li>{@code decimal} is built without {@link java.math.BigInteger}: the
 *       digits are multiplied into a 128-bit limb array by hand. That is not
 *       zeal - the library forbids the class outright, because a
 *       {@code BigInteger} is an immutable heap object that cannot be
 *       zeroed.</li>
 * </ul>
 */
public final class TdsParameters {

    /** Beyond this a {@code nvarchar} has to travel as {@code MAX}. */
    private static final int MAX_NVARCHAR_CHARS = 4000;
    /** Beyond this a {@code varbinary} has to travel as {@code MAX}. */
    private static final int MAX_VARBINARY_BYTES = 8000;
    /** The declared byte length of a {@code decimal} value: sign plus 16. */
    private static final int DECIMAL_SIZE = 17;
    /** SQL Server's largest precision. */
    private static final int MAX_PRECISION = 38;
    /** 100-nanosecond ticks, the finest SQL Server offers. */
    private static final int TIME_SCALE = 7;
    /** Days from 0001-01-01 to 1970-01-01 - the epoch the wire counts from. */
    private static final int DAYS_1970 = 719162;

    private Object[] values = new Object[8]; // seclume-allow: statement parameters, user payload and never a secret
    private int count;

    /** Built empty; the values arrive through {@link #set}. */
    public TdsParameters() {
    }

    /** Sets a parameter; the index is 1-based, as JDBC counts. */
    public void set(int index, Object value) throws SQLException {
        if (index < 1) {
            throw new SQLException("parameter index " + index + " is not 1 or more");
        }
        if (index > values.length) {
            values = java.util.Arrays.copyOf(values, Math.max(index, values.length * 2));
        }
        values[index - 1] = value;
        count = Math.max(count, index);
    }

    public Object get(int index) {
        return index >= 1 && index <= count ? values[index - 1] : null;
    }

    public int count() {
        return count;
    }

    public void clear() {
        java.util.Arrays.fill(values, null);
        count = 0;
    }

    /** The declaration {@code sp_executesql} needs as its second argument. */
    public String declaration() throws SQLException {
        StringBuilder text = new StringBuilder(); // seclume-allow: a type declaration, never a secret
        for (int i = 0; i < count; i++) {
            if (i > 0) {
                text.append(',');
            }
            text.append("@P").append(i).append(' ').append(typeName(values[i]));
        }
        return text.toString();
    }


    /**
     * An {@code int} the server is asked to write back - an OUTPUT parameter.
     *
     * <p>The status byte carries {@code fByRefValue}, and the value goes over
     * as {@code NULL}: what matters is what comes <b>back</b>, in a
     * {@code RETURNVALUE} token. This is what opening a server-side cursor
     * needs - the handle exists only after the server has made it.
     */
    public static void writeOutputInt(WireBuffer out, String name, Integer value) {
        putBVarchar(out, name);
        out.putByte((byte) 0x01);                     // fByRefValue: OUTPUT
        out.putByte((byte) TdsTypes.INTN);
        out.putByte((byte) 4);                        // maximum width
        if (value == null) {
            out.putByte((byte) 0);                    // NULL going in
        } else {
            out.putByte((byte) 4);
            out.putUnsignedLe(value, 4);
        }
    }

    /** Text under a name - for a procedure whose argument order is unknown. */
    public static void writeNamedText(WireBuffer out, String name, String text) {
        putBVarchar(out, name);
        out.putByte((byte) 0);                        // input parameter
        putText(out, text);
    }

    /** An ordinary {@code int} argument of a stored procedure. */
    public static void writeInt(WireBuffer out, String name, int value) {
        putBVarchar(out, name);
        out.putByte((byte) 0);                        // input parameter
        out.putByte((byte) TdsTypes.INTN);
        out.putByte((byte) 4);
        out.putByte((byte) 4);
        out.putUnsignedLe(value, 4);
    }

    /** Writes every parameter as its own RPC block. */
    public void writeAll(WireBuffer out) throws SQLException {
        for (int i = 0; i < count; i++) {
            write(out, "@P" + i, values[i]);
        }
    }

    // ---- one parameter ---------------------------------------------------

    /**
     * The declared type - it has to match the bytes that {@link #write} puts
     * out, byte for byte.
     */
    private static String typeName(Object value) throws SQLException {
        return switch (value) {
            case null -> "nvarchar(1)";
            case Boolean ignored -> "bit";
            case Byte ignored -> "int";
            case Short ignored -> "int";
            case Integer ignored -> "int";
            case Long ignored -> "bigint";
            case Float ignored -> "real";
            case Double ignored -> "float";
            case BigDecimal number -> "decimal(" + MAX_PRECISION + "," + scaleOf(number) + ")";
            case String text -> text.length() > MAX_NVARCHAR_CHARS
                    ? "nvarchar(max)"
                    : "nvarchar(" + Math.max(text.length(), 1) + ")";
            case byte[] bytes -> bytes.length > MAX_VARBINARY_BYTES
                    ? "varbinary(max)"
                    : "varbinary(" + Math.max(bytes.length, 1) + ")";
            case java.sql.Date ignored -> "date";
            case LocalDate ignored -> "date";
            case java.sql.Time ignored -> "time(" + TIME_SCALE + ")";
            case LocalTime ignored -> "time(" + TIME_SCALE + ")";
            case java.sql.Timestamp ignored -> "datetime2(" + TIME_SCALE + ")";
            case LocalDateTime ignored -> "datetime2(" + TIME_SCALE + ")";
            case OffsetDateTime ignored -> "datetimeoffset(" + TIME_SCALE + ")";
            default -> throw unsupported(value);
        };
    }

    /** Writes one parameter: name, flags, type description, value. */
    private static void write(WireBuffer out, String name, Object value) throws SQLException {
        putBVarchar(out, name);
        out.putByte((byte) 0);                        // input parameter
        switch (value) {
            case null -> {
                out.putByte((byte) TdsTypes.NVARCHAR);
                out.putShortLe((short) 2);
                putCollation(out);
                out.putShortLe((short) 0xffff);       // NULL
            }
            case Boolean flag -> {
                out.putByte((byte) TdsTypes.BITN);
                out.putByte((byte) 1);
                out.putByte((byte) 1);
                out.putByte((byte) (flag ? 1 : 0));
            }
            case Byte number -> putInt(out, number.longValue(), 4);
            case Short number -> putInt(out, number.longValue(), 4);
            case Integer number -> putInt(out, number.longValue(), 4);
            case Long number -> putInt(out, number, 8);
            case Float number -> {
                out.putByte((byte) TdsTypes.FLTN);
                out.putByte((byte) 4);
                out.putByte((byte) 4);
                out.putIntLe(Float.floatToIntBits(number));
            }
            case Double number -> {
                out.putByte((byte) TdsTypes.FLTN);
                out.putByte((byte) 8);
                out.putByte((byte) 8);
                out.putLongLe(Double.doubleToLongBits(number));
            }
            case BigDecimal number -> putDecimal(out, number);
            case String text -> putText(out, text);
            case byte[] bytes -> putBinary(out, bytes);
            case java.sql.Date date -> putDate(out, date.toLocalDate());
            case LocalDate date -> putDate(out, date);
            case java.sql.Time time -> putTime(out, time.toLocalTime());
            case LocalTime time -> putTime(out, time);
            case java.sql.Timestamp stamp -> putDateTime2(out, stamp.toLocalDateTime());
            case LocalDateTime stamp -> putDateTime2(out, stamp);
            case OffsetDateTime stamp -> putDateTimeOffset(out, stamp);
            default -> throw unsupported(value);
        }
    }

    /** An integer as {@code intn} - the length says which width. */
    private static void putInt(WireBuffer out, long value, int width) {
        out.putByte((byte) TdsTypes.INTN);
        out.putByte((byte) width);
        out.putByte((byte) width);
        out.putUnsignedLe(value, width);
    }

    /**
     * Text as {@code nvarchar}. Above 4000 characters it no longer fits into
     * the two-byte length and has to go as {@code MAX}, in chunks.
     */
    private static void putText(WireBuffer out, String text) {
        out.putByte((byte) TdsTypes.NVARCHAR);
        boolean large = text.length() > MAX_NVARCHAR_CHARS;
        out.putShortLe((short) (large ? 0xffff : Math.max(text.length(), 1) * 2));
        putCollation(out);
        if (large) {
            out.putLongLe((long) text.length() * 2);  // total length
            out.putIntLe(text.length() * 2);          // one chunk is enough
            putUtf16(out, text);
            out.putIntLe(0);                          // terminator
            return;
        }
        out.putShortLe((short) (text.length() * 2));
        putUtf16(out, text);
    }

    private static void putBinary(WireBuffer out, byte[] bytes) {
        out.putByte((byte) TdsTypes.BIGVARBINARY);
        boolean large = bytes.length > MAX_VARBINARY_BYTES;
        out.putShortLe((short) (large ? 0xffff : Math.max(bytes.length, 1)));
        if (large) {
            out.putLongLe(bytes.length);
            out.putIntLe(bytes.length);
            for (byte b : bytes) {
                out.putByte(b);
            }
            out.putIntLe(0);
            return;
        }
        out.putShortLe((short) bytes.length);
        for (byte b : bytes) {
            out.putByte(b);
        }
    }

    private static void putDate(WireBuffer out, LocalDate date) {
        out.putByte((byte) TdsTypes.DATEN);
        out.putByte((byte) 3);
        out.putUnsignedLe(date.toEpochDay() + DAYS_1970, 3);
    }

    private static void putTime(WireBuffer out, LocalTime time) {
        out.putByte((byte) TdsTypes.TIMEN);
        out.putByte((byte) TIME_SCALE);
        out.putByte((byte) 5);
        out.putUnsignedLe(time.toNanoOfDay() / 100, 5);
    }

    private static void putDateTime2(WireBuffer out, LocalDateTime stamp) {
        out.putByte((byte) TdsTypes.DATETIME2N);
        out.putByte((byte) TIME_SCALE);
        out.putByte((byte) 8);
        out.putUnsignedLe(stamp.toLocalTime().toNanoOfDay() / 100, 5);
        out.putUnsignedLe(stamp.toLocalDate().toEpochDay() + DAYS_1970, 3);
    }

    /**
     * {@code datetimeoffset} carries UTC on the wire, with the offset beside
     * it - not the local time. Sending the local time instead is a mistake
     * that shifts every value by the offset and looks plausible.
     */
    private static void putDateTimeOffset(WireBuffer out, OffsetDateTime stamp) {
        LocalDateTime utc = stamp.withOffsetSameInstant(java.time.ZoneOffset.UTC)
                .toLocalDateTime();
        out.putByte((byte) TdsTypes.DATETIMEOFFSETN);
        out.putByte((byte) TIME_SCALE);
        out.putByte((byte) 10);
        out.putUnsignedLe(utc.toLocalTime().toNanoOfDay() / 100, 5);
        out.putUnsignedLe(utc.toLocalDate().toEpochDay() + DAYS_1970, 3);
        out.putUnsignedLe(stamp.getOffset().getTotalSeconds() / 60, 2);
    }

    /**
     * {@code decimal}: a sign byte and sixteen bytes of magnitude, least
     * significant first.
     *
     * <p>The magnitude is built from the digit text by multiplying into a
     * 128-bit limb array - no {@code BigInteger}, which the library does not
     * allow anywhere.
     */
    private static void putDecimal(WireBuffer out, BigDecimal number) throws SQLException {
        int scale = scaleOf(number);
        BigDecimal scaled = number.setScale(scale, java.math.RoundingMode.UNNECESSARY);
        String digits = scaled.abs().toPlainString().replace(".", "");
        if (digits.length() > MAX_PRECISION) {
            throw new SQLException("the value has " + digits.length()
                    + " digits, SQL Server takes at most " + MAX_PRECISION, "22003");
        }
        int[] limbs = new int[4]; // seclume-allow: a numeric parameter, user payload and never a secret
        for (int i = 0; i < digits.length(); i++) {
            multiplyAdd(limbs, digits.charAt(i) - '0');
        }
        out.putByte((byte) TdsTypes.DECIMALN);
        out.putByte((byte) DECIMAL_SIZE);
        out.putByte((byte) MAX_PRECISION);
        out.putByte((byte) scale);
        out.putByte((byte) DECIMAL_SIZE);
        out.putByte((byte) (number.signum() < 0 ? 0 : 1));
        for (int limb : limbs) {
            out.putUnsignedLe(limb & 0xffffffffL, 4);
        }
    }

    /** {@code limbs = limbs * 10 + digit}, little-endian, 128 bits wide. */
    private static void multiplyAdd(int[] limbs, int digit) {
        long carry = digit;
        for (int i = 0; i < limbs.length; i++) {
            long product = (limbs[i] & 0xffffffffL) * 10 + carry;
            limbs[i] = (int) product;
            carry = product >>> 32;
        }
    }

    private static int scaleOf(BigDecimal number) throws SQLException {
        int scale = number.scale();
        if (scale < 0) {
            // A negative scale means trailing zeroes that are not written out;
            // SQL Server has no such thing, so it gets the plain form.
            return 0;
        }
        if (scale > MAX_PRECISION) {
            throw new SQLException("a scale of " + scale + " is more than SQL Server allows",
                    "22003");
        }
        return scale;
    }

    // ---- pieces every parameter needs ------------------------------------

    /** A name: one byte of character count, then UTF-16LE. */
    static void putBVarchar(WireBuffer out, String text) {
        out.putByte((byte) text.length());
        putUtf16(out, text);
    }

    static void putUtf16(WireBuffer out, String text) {
        for (int i = 0; i < text.length(); i++) {
            out.putShortLe((short) text.charAt(i));
        }
    }

    /**
     * The five collation bytes. Zero means: whatever the server has - which is
     * the right answer for a parameter, because the value travels as UTF-16
     * and is converted by the server, not here.
     */
    private static void putCollation(WireBuffer out) {
        out.putZeroes(5);
    }

    /** An {@code nvarchar} parameter without a name - for sp_executesql itself. */
    public static void writeStatementText(WireBuffer out, String text) {
        out.putByte((byte) 0);                        // no name
        out.putByte((byte) 0);                        // input parameter
        putText(out, text);
    }

    private static SQLException unsupported(Object value) {
        return new SQLException("seclume does not send a "
                + value.getClass().getName() + " as a parameter - convert it to a "
                + "String, a number, a byte[] or a date type first", "22005");
    }
}
