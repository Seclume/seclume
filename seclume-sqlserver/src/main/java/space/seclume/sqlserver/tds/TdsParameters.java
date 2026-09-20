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
    /**
     * The scales a decimal is declared with - rounded up, not exact.
     *
     * <p>A compiled statement is compiled <b>with</b> its declaration, so a
     * declaration that follows the value needs a new compilation whenever
     * the value's shape changes. For text and binary that is settled by
     * declaring the full width (see {@link #typeName}); a decimal's scale
     * cannot be widened without limit, so it is rounded up to one of these.
     */
    private static final int[] SCALES = {0, 2, 4, 8, 16, 30};
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

    /** The smallest of the given sizes that holds this one. */
    private static int bucket(int needed, int[] sizes) {
        for (int size : sizes) {
            if (needed <= size) {
                return size;
            }
        }
        return sizes[sizes.length - 1];
    }

    // ---- one parameter ---------------------------------------------------

    /**
     * The declared type - it has to match the bytes that {@link #write} puts
     * out, byte for byte.
     */
    private static String typeName(Object value) throws SQLException {
        return switch (value) {
            case null -> "nvarchar(" + MAX_NVARCHAR_CHARS + ")";
            case TypedNull typed -> typed.declaration();
            case Boolean ignored -> "bit";
            case Byte ignored -> "int";
            case Short ignored -> "int";
            case Integer ignored -> "int";
            case Long ignored -> "bigint";
            case Float ignored -> "real";
            case Double ignored -> "float";
            case BigDecimal number -> "decimal(" + MAX_PRECISION + ","
                    + bucket(scaleOf(number), SCALES) + ")";
            // The full width, not the value's: a parameter is declared once
            // per compiled statement and the value's own length travels with
            // the value. Declaring the length made a batch of two hundred
            // rows recompile on every row whose text was a character longer,
            // and - worse - let a handle compiled for a null (nvarchar(1))
            // truncate the next row's "DORMANT" to "D" without a word. This
            // is also what the vendor's driver sends.
            case String text -> text.length() > MAX_NVARCHAR_CHARS
                    ? "nvarchar(max)" : "nvarchar(" + MAX_NVARCHAR_CHARS + ")";
            case byte[] bytes -> bytes.length > MAX_VARBINARY_BYTES
                    ? "varbinary(max)" : "varbinary(" + MAX_VARBINARY_BYTES + ")";
            case java.sql.Date ignored -> "date";
            case LocalDate ignored -> "date";
            case java.sql.Time ignored -> "time(" + TIME_SCALE + ")";
            case LocalTime ignored -> "time(" + TIME_SCALE + ")";
            case java.sql.Timestamp ignored -> "datetime2(" + TIME_SCALE + ")";
            case LocalDateTime ignored -> "datetime2(" + TIME_SCALE + ")";
            case OffsetDateTime ignored -> "datetimeoffset(" + TIME_SCALE + ")";
            case java.util.UUID ignored -> "uniqueidentifier";
            default -> throw unsupported(value);
        };
    }

    /** Writes one parameter: name, flags, type description, value. */
    private static void write(WireBuffer out, String name, Object value) throws SQLException {
        putBVarchar(out, name);
        out.putByte((byte) 0);                        // input parameter
        switch (value) {
            case null -> putNull(out, java.sql.Types.NULL);
            case TypedNull typed -> putNull(out, typed.sqlType());
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
            case java.util.UUID id -> putGuid(out, id);
            default -> throw unsupported(value);
        }
    }

    /**
     * A {@code uniqueidentifier}: sixteen bytes, and not in the order the
     * text has them.
     *
     * <p>SQL Server stores the first three groups little-endian and the last
     * two as written. A GUID with those bytes the wrong way round still
     * looks like a GUID and still sorts and joins - it is simply a different
     * one, which is why the order is spelled out here as it is in
     * {@code TdsValues} for the way back.
     */
    private static void putGuid(WireBuffer out, java.util.UUID id) {
        out.putByte((byte) TdsTypes.GUID);
        out.putByte((byte) 16);                       // the declared length
        out.putByte((byte) 16);                       // the length of this value
        long high = id.getMostSignificantBits();
        long low = id.getLeastSignificantBits();
        out.putIntLe((int) (high >>> 32));            // the first group, swapped
        out.putShortLe((short) (high >>> 16));        // the second
        out.putShortLe((short) high);                 // the third
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.putByte((byte) (low >>> shift));      // the last two, as written
        }
    }

    /**
     * A null with the type the caller named.
     *
     * <p>An untyped null is declared {@code nvarchar(1)}, and SQL Server
     * refuses to put that into a {@code varbinary} or a {@code date}:
     * "Implicit conversion from data type nvarchar to varbinary is not
     * allowed". Every entity with a null {@code byte[]} in it therefore
     * failed to save. {@code setNull} carries the type for exactly this
     * reason, and here it is used.
     */
    private static void putNull(WireBuffer out, int sqlType) {
        switch (sqlType) {
            case java.sql.Types.BINARY, java.sql.Types.VARBINARY,
                 java.sql.Types.LONGVARBINARY, java.sql.Types.BLOB -> {
                out.putByte((byte) TdsTypes.BIGVARBINARY);
                out.putShortLe((short) 1);
                out.putShortLe((short) 0xffff);       // NULL
            }
            default -> {
                out.putByte((byte) TdsTypes.NVARCHAR);
                out.putShortLe((short) 2);
                putCollation(out);
                out.putShortLe((short) 0xffff);       // NULL
            }
        }
    }

    /** What a null of that type is declared as in the RPC's parameter list. */
    public record TypedNull(int sqlType) {

        String declaration() {
            return switch (sqlType) {
                case java.sql.Types.BINARY, java.sql.Types.VARBINARY,
                     java.sql.Types.LONGVARBINARY, java.sql.Types.BLOB ->
                        "varbinary(" + MAX_VARBINARY_BYTES + ")";
                case java.sql.Types.DATE -> "date";
                case java.sql.Types.TIME -> "time";
                case java.sql.Types.TIMESTAMP -> "datetime2";
                case java.sql.Types.TIMESTAMP_WITH_TIMEZONE -> "datetimeoffset";
                case java.sql.Types.TINYINT, java.sql.Types.SMALLINT,
                     java.sql.Types.INTEGER -> "int";
                case java.sql.Types.BIGINT -> "bigint";
                case java.sql.Types.BOOLEAN, java.sql.Types.BIT -> "bit";
                case java.sql.Types.REAL -> "real";
                case java.sql.Types.FLOAT, java.sql.Types.DOUBLE -> "float";
                case java.sql.Types.DECIMAL, java.sql.Types.NUMERIC -> "decimal(38,10)";
                default -> "nvarchar(" + MAX_NVARCHAR_CHARS + ")";
            };
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
