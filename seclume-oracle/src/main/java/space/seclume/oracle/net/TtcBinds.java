package space.seclume.oracle.net;

import java.math.BigDecimal;
import java.sql.SQLException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import space.seclume.internal.WireBuffer;

/**
 * The bind variables of a statement.
 *
 * <p>Oracle sends them in two parts, and they sit far apart in the message:
 * first a <b>description</b> per variable - type, buffer size, character set -
 * behind the statement text, and then the <b>values</b>, introduced by a
 * {@code ROW_DATA} byte. Both are written here so that the two lists cannot
 * drift apart.
 *
 * <p>The shapes are taken from a recorded exchange with Oracle Free 23ai
 * ({@code insert into ... values (:1, :2)} with a number and a string), not
 * from a description. A number describes itself with a buffer of 22 bytes and
 * no character set, a string with four bytes per character and character set
 * 873.
 */
public final class TtcBinds {

    /** How many bytes a NUMBER takes at most. */
    private static final int NUMBER_SIZE = 22;
    /** How many bytes a DATE takes. */
    private static final int DATE_SIZE = 7;
    /** Bytes per character the server is told to expect. */
    private static final int BYTES_PER_CHARACTER = 4;
    /** AL32UTF8, the character set this driver talks. */
    private static final int CHARSET = 873;
    /** The character set form of a normal string. */
    private static final int CSFRM_IMPLICIT = 1;
    /** A buffer size for a bind whose value is null. */
    private static final int NULL_SIZE = 1;
    /** Oracle's offset for the century and the year in a DATE. */
    private static final int YEAR_BIAS = 100;
    /** Up to this length a value carries a single length byte. */
    private static final int SHORT_LENGTH = 252;
    /** The length byte that says "chunks follow". */
    private static final int CHUNKED = 0xfe;
    /** How much goes into one chunk. */
    private static final int CHUNK_SIZE = 32767;

    private final List<Object> values = new ArrayList<>();

    /** A fresh, empty list of bind variables. */
    public TtcBinds() {
    }

    /** Sets a value; the index is the JDBC one and starts at one. */
    public void set(int index, Object value) throws SQLException {
        if (index < 1) {
            throw new SQLException("a parameter index starts at 1, not " + index);
        }
        while (values.size() < index) {
            values.add(null);
        }
        values.set(index - 1, value);
    }


    /**
     * A bind the <b>server</b> fills - the {@code into} of a DML returning.
     *
     * <p>Measured against the reference client: such a bind is described like
     * any other, with the same flag byte, and simply carries <b>no value</b> in
     * the row data. The server knows it is an output from the statement text.
     * The answer then arrives as a {@code ROW_DATA} message in front of
     * everything else - see {@code TtcResult#returned}.
     */
    public void addOutput() {
        values.add(OUTPUT);
    }

    /** Whether this list has an output bind in it. */
    public boolean hasOutput() {
        return values.contains(OUTPUT);
    }

    /** Marks a place the server writes into; never sent as a value. */
    private static final Object OUTPUT = new Object();

    /** The value at a JDBC index, or {@code null}. */
    public Object get(int index) {
        return index >= 1 && index <= values.size() ? values.get(index - 1) : null;
    }

    public int count() {
        return values.size();
    }

    public void clear() {
        values.clear();
    }

    /**
     * The description of every variable, in order.
     *
     * <p>Thirteen fields each, and the last four are zero for everything this
     * driver sends. The character set is the only one that depends on the
     * value: a number has none, a string has 873.
     */
    public void putDescriptors(WireBuffer out) throws SQLException {
        putDescriptors(out, null);
    }

    /**
     * The same, with the buffer sizes decided outside.
     *
     * <p>A batch describes its variables <b>once</b> and then sends many sets
     * of values. The description has to fit the widest of them: a text column
     * whose first row holds three characters and whose tenth holds forty would
     * otherwise be described three characters wide. The caller walks the rows
     * first and passes the maximum per column.
     *
     * @param sizes the buffer size per variable, or {@code null} for this row
     */
    public void putDescriptors(WireBuffer out, long[] sizes) throws SQLException {
        for (int index = 0; index < values.size(); index++) {
            Object value = values.get(index);
            int type = value == OUTPUT ? OracleColumn.TYPE_NUMBER : typeOf(value);
            out.putByte((byte) type);
            out.putByte((byte) 1);                     // flags, always one here
            out.putByte((byte) 0);                     // precision
            out.putByte((byte) 0);                     // scale
            TtcParameters.putNumber(out, value == OUTPUT ? NUMBER_SIZE
                    : (sizes == null ? bufferSizeOf(value, type) : sizes[index]));
            TtcParameters.putNumber(out, 0);           // largest number of array elements
            TtcParameters.putNumber(out, 0);           // continuation flags
            out.putByte((byte) 0);                     // object id
            TtcParameters.putNumber(out, 0);           // version
            boolean text = type == OracleColumn.TYPE_VARCHAR;
            TtcParameters.putNumber(out, text ? CHARSET : 0);
            out.putByte((byte) (text ? CSFRM_IMPLICIT : 0));
            TtcParameters.putNumber(out, 0);           // largest character count
            TtcParameters.putNumber(out, 0);           // oaccolid
        }
    }

    /**
     * The values, introduced by the {@code ROW_DATA} byte.
     *
     * <p>A null is a length of zero and nothing else - the same shape a null
     * column has in a row coming back.
     */
    public void putValues(WireBuffer out) throws SQLException {
        out.putByte((byte) TtcMessage.TYPE_ROW_DATA);
        for (Object value : values) {
            if (value == OUTPUT) {
                // Nothing: the server writes here, it does not read.
                continue;
            }
            putValue(out, value);
        }
    }

    private static void putValue(WireBuffer out, Object value) throws SQLException {
        switch (value) {
            case null -> out.putByte((byte) 0);
            case Boolean flag -> OracleNumber.encode(out, flag ? 1 : 0);
            case Byte number -> OracleNumber.encode(out, number.longValue());
            case Short number -> OracleNumber.encode(out, number.longValue());
            case Integer number -> OracleNumber.encode(out, number.longValue());
            case Long number -> OracleNumber.encode(out, number);
            case Float number -> OracleNumber.encodeText(out,
                    BigDecimal.valueOf(number.doubleValue()).toPlainString());
            case Double number -> OracleNumber.encodeText(out,
                    BigDecimal.valueOf(number).toPlainString());
            case BigDecimal number -> OracleNumber.encodeText(out, number.toPlainString());
            case String text -> putText(out, text);
            case byte[] bytes -> putBytes(out, bytes);
            case LocalDate date -> putDate(out, date.atStartOfDay());
            case LocalDateTime stamp -> putDate(out, stamp);
            case java.sql.Date date -> putDate(out, date.toLocalDate().atStartOfDay());
            case java.sql.Timestamp stamp -> putDate(out, stamp.toLocalDateTime());
            default -> throw new SQLException("seclume cannot send a "
                    + value.getClass().getName() + " to Oracle as a bind variable");
        }
    }

    /**
     * How much room this row would need per variable - for a batch that has
     * to describe them all with one size.
     */
    public void measure(long[] sizes) throws SQLException {
        for (int index = 0; index < values.size() && index < sizes.length; index++) {
            Object value = values.get(index);
            sizes[index] = Math.max(sizes[index], bufferSizeOf(value, typeOf(value)));
        }
    }

    /** The type byte the server is told about. */
    private static int typeOf(Object value) throws SQLException {
        return switch (value) {
            case null -> OracleColumn.TYPE_VARCHAR;
            case Boolean ignored -> OracleColumn.TYPE_NUMBER;
            case Byte ignored -> OracleColumn.TYPE_NUMBER;
            case Short ignored -> OracleColumn.TYPE_NUMBER;
            case Integer ignored -> OracleColumn.TYPE_NUMBER;
            case Long ignored -> OracleColumn.TYPE_NUMBER;
            case Float ignored -> OracleColumn.TYPE_NUMBER;
            case Double ignored -> OracleColumn.TYPE_NUMBER;
            case BigDecimal ignored -> OracleColumn.TYPE_NUMBER;
            case String ignored -> OracleColumn.TYPE_VARCHAR;
            case byte[] ignored -> OracleColumn.TYPE_RAW;
            case LocalDate ignored -> OracleColumn.TYPE_DATE;
            case LocalDateTime ignored -> OracleColumn.TYPE_DATE;
            case java.sql.Date ignored -> OracleColumn.TYPE_DATE;
            case java.sql.Timestamp ignored -> OracleColumn.TYPE_DATE;
            default -> throw new SQLException("seclume cannot send a "
                    + value.getClass().getName() + " to Oracle as a bind variable");
        };
    }

    /**
     * How much room the server should keep.
     *
     * <p>For a string that is four bytes per character, not the length of this
     * one: the same statement runs again with other values, and a buffer cut
     * to the first value would have to be renegotiated every time.
     */
    private static long bufferSizeOf(Object value, int type) {
        return switch (type) {
            case OracleColumn.TYPE_NUMBER -> NUMBER_SIZE;
            case OracleColumn.TYPE_DATE -> DATE_SIZE;
            case OracleColumn.TYPE_RAW -> Math.max(((byte[]) value).length, 1);
            default -> value == null ? NULL_SIZE
                    : Math.max(((String) value).length() * BYTES_PER_CHARACTER, 1);
        };
    }

    private static void putText(WireBuffer out, String text) {
        int start = out.position();
        out.putByte((byte) 0);                         // room for the length
        out.putText(text);
        int length = out.position() - start - 1;
        if (length <= SHORT_LENGTH) {
            out.putByteAt(start, (byte) length);
            return;
        }
        // Too long for a single length byte: the bytes have to be moved apart
        // so that every chunk can carry its own length. Rare enough to be
        // worth the copy rather than a second encoding pass.
        byte[] bytes = new byte[length]; // seclume-allow: a bind value on its way out, never a secret
        for (int i = 0; i < length; i++) {
            bytes[i] = out.getByte(start + 1 + i);
        }
        out.position(start);
        putBytes(out, bytes);
    }

    private static void putBytes(WireBuffer out, byte[] bytes) {
        if (bytes.length <= SHORT_LENGTH) {
            out.putByte((byte) bytes.length);
            out.putBytes(java.lang.foreign.MemorySegment.ofArray(bytes), 0, bytes.length);
            return;
        }
        out.putByte((byte) CHUNKED);
        int at = 0;
        while (at < bytes.length) {
            int chunk = Math.min(CHUNK_SIZE, bytes.length - at);
            TtcParameters.putNumber(out, chunk);
            out.putBytes(java.lang.foreign.MemorySegment.ofArray(bytes), at, chunk);
            at += chunk;
        }
        TtcParameters.putNumber(out, 0);
    }

    /**
     * Oracle's seven bytes for a point in time: century and year both shifted
     * by 100 - so that no byte is zero and the bytes sort - and hour, minute
     * and second shifted by one.
     */
    private static void putDate(WireBuffer out, LocalDateTime stamp) {
        out.putByte((byte) DATE_SIZE);
        int year = stamp.getYear();
        out.putByte((byte) (year / 100 + YEAR_BIAS));
        out.putByte((byte) (year % 100 + YEAR_BIAS));
        out.putByte((byte) stamp.getMonthValue());
        out.putByte((byte) stamp.getDayOfMonth());
        out.putByte((byte) (stamp.getHour() + 1));
        out.putByte((byte) (stamp.getMinute() + 1));
        out.putByte((byte) (stamp.getSecond() + 1));
    }
}
