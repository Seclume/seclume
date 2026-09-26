package space.seclume.mysql;

import java.lang.foreign.MemorySegment;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.sql.Time;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.Arrays;
import java.util.UUID;

import space.seclume.internal.WireBuffer;
import space.seclume.mysql.wire.MyPackets;

/**
 * The parameters of a prepared statement.
 *
 * <p>{@code COM_STMT_EXECUTE} writes them in three parts: first a bitmask for
 * the NULL values, then two bytes of type tag per parameter, then the values
 * themselves.
 *
 * <p>Numbers go out as numbers - eight bytes for a {@code long} instead of up
 * to twenty digits - everything else as a string with the length in front. That
 * is not a makeshift: MySQL converts a string into the type of the column, and
 * for {@code decimal} or {@code datetime} the text form is the more precise
 * choice, because it introduces no rounding through an intermediate format.
 *
 * <p>No value is built into the SQL text. Parameters go over the wire as
 * parameters - SQL injection is not a danger warded off here, it does not exist
 * at all.
 */
public final class MyParameters {

    private Object[] values;
    private int count;

    public MyParameters(int expected) {
        this.values = new Object[Math.max(expected, 8)];
    }

    public int count() {
        return count;
    }

    public void clear() {
        Arrays.fill(values, null);
        count = 0;
    }

    /**
     * Sets the parameter with a 1-based index, the way JDBC counts.
     *
     * <p>A {@link java.sql.SQLException} and not an
     * {@code IllegalArgumentException} for the index: this is reached straight
     * from {@code setInt(0, ...)}, which is a caller's off-by-one, and the
     * caller's {@code catch} is written against the JDBC signature. Oracle and
     * SQL Server already refused it this way; these two did not.
     */
    public void set(int index, Object value) throws java.sql.SQLException {
        if (index < 1) {
            throw new java.sql.SQLException(
                    "parameter indexes start at 1, got " + index, "07009");
        }
        if (index > values.length) {
            values = Arrays.copyOf(values, Math.max(index, values.length * 2));
        }
        values[index - 1] = value;
        count = Math.max(count, index);
    }

    public Object get(int index) {
        return index >= 1 && index <= count ? values[index - 1] : null;
    }

    /** Writes bitmask, types and values into the execute packet. */
    void write(WireBuffer out, int expected) {
        if (expected == 0) {
            return;
        }
        int bitmapLength = (expected + 7) / 8;
        int bitmapAt = out.position();
        out.putZeroes(bitmapLength);
        for (int i = 0; i < expected; i++) {
            if (value(i) == null) {
                int at = bitmapAt + i / 8;
                out.putByteAt(at, (byte) (out.getByte(at) | (1 << (i % 8))));
            }
        }
        // 1 = "the types are in this packet". Without that byte the server
        // expects the types from an earlier execution.
        out.putByte((byte) 1);
        for (int i = 0; i < expected; i++) {
            Object value = value(i);
            out.putShortLe((short) typeOf(value));
        }
        for (int i = 0; i < expected; i++) {
            Object value = value(i);
            if (value != null) {
                writeValue(out, value);
            }
        }
    }

    private Object value(int index) {
        return index < count ? values[index] : null;
    }

    /** The type tag; the upper byte carries the unsigned bit. */
    private static int typeOf(Object value) {
        if (value == null) {
            return MyTypes.NULL;
        }
        if (value instanceof Long || value instanceof Integer || value instanceof Short
                || value instanceof Byte) {
            return MyTypes.LONGLONG;
        }
        if (value instanceof Double || value instanceof Float) {
            return MyTypes.DOUBLE;
        }
        if (value instanceof Boolean) {
            // As a number, not as the text "1": a bit(1) column takes the
            // text as one character, which is eight bits, and the server
            // answers "Data too long for column". Hibernate maps a boolean
            // to bit(1) on MySQL, so this is the ordinary case and not an
            // exotic one.
            return MyTypes.LONGLONG;
        }
        if (value instanceof byte[] || value instanceof UUID) {
            return MyTypes.BLOB;
        }
        return MyTypes.VAR_STRING;
    }

    private static void writeValue(WireBuffer out, Object value) {
        if (value instanceof Long || value instanceof Integer || value instanceof Short
                || value instanceof Byte) {
            out.putLongLe(((Number) value).longValue());
            return;
        }
        if (value instanceof Double || value instanceof Float) {
            out.putLongLe(Double.doubleToLongBits(((Number) value).doubleValue()));
            return;
        }
        if (value instanceof Boolean flag) {
            out.putLongLe(flag ? 1 : 0);
            return;
        }
        if (value instanceof space.seclume.internal.jdbc.NativeValue nativeValue) {
            // Straight from the caller's memory into the send buffer, with no
            // byte[] in between - see space.seclume.SensitiveParameters. The
            // type tag is VAR_STRING, so the bytes are the value's text.
            MyPackets.writeLengthEncoded(out, nativeValue.length());
            out.putBytes(nativeValue.memory(), 0, nativeValue.length());
            return;
        }
        if (value instanceof byte[] bytes) {
            MyPackets.writeLengthEncoded(out, bytes.length);
            out.putBytes(MemorySegment.ofArray(bytes), 0, bytes.length);
            return;
        }
        if (value instanceof UUID id) {
            // Sixteen bytes, most significant first - what Hibernate's
            // binary(16) column holds. As the thirty-six characters of its
            // text form it would not fit, and the server says so with "Data
            // too long" rather than storing something wrong.
            MyPackets.writeLengthEncoded(out, 16);
            for (int shift = 56; shift >= 0; shift -= 8) {
                out.putByte((byte) (id.getMostSignificantBits() >>> shift));
            }
            for (int shift = 56; shift >= 0; shift -= 8) {
                out.putByte((byte) (id.getLeastSignificantBits() >>> shift));
            }
            return;
        }
        byte[] text = encode(value).getBytes(StandardCharsets.UTF_8); // seclume-allow: user payload, not a database password
        MyPackets.writeLengthEncoded(out, text.length);
        out.putBytes(MemorySegment.ofArray(text), 0, text.length);
    }

    /**
     * The text form MySQL expects for this type.
     *
     * <p>Not {@code toString()}: {@code Boolean.toString()} yields "true",
     * MySQL wants 1 or 0; {@code BigDecimal.toString()} can slip into
     * exponential notation, which the server rounds differently; and a
     * {@code LocalDateTime} carries a 'T' in the middle that MySQL can make
     * nothing of.
     */
    private static String encode(Object value) {
        if (value instanceof Boolean flag) {
            return flag ? "1" : "0";
        }
        if (value instanceof BigDecimal decimal) {
            return decimal.toPlainString();
        }
        if (value instanceof Timestamp timestamp) {
            return timestamp.toLocalDateTime().toString().replace('T', ' ');
        }
        if (value instanceof Date date) {
            return date.toLocalDate().toString();
        }
        if (value instanceof Time time) {
            return time.toLocalTime().toString();
        }
        if (value instanceof LocalDateTime dateTime) {
            return dateTime.toString().replace('T', ' ');
        }
        if (value instanceof LocalDate date) {
            return date.toString();
        }
        if (value instanceof LocalTime time) {
            return time.toString();
        }
        if (value instanceof java.time.OffsetDateTime stamp) {
            // MySQL's datetime has no zone, so what is written are the
            // wall-clock fields of the value itself. A caller who means a
            // point in time regardless of zone passes a Timestamp with a
            // calendar, which is what Hibernate does.
            return stamp.toLocalDateTime().toString().replace('T', ' ');
        }
        if (value instanceof java.time.Instant instant) {
            return java.time.LocalDateTime.ofInstant(instant, java.time.ZoneOffset.UTC)
                    .toString().replace('T', ' ');
        }
        if (value instanceof Number || value instanceof CharSequence
                || value instanceof Character) {
            return value.toString();
        }
        throw new IllegalArgumentException(
                "seclume does not know how to send a " + value.getClass().getName()
                + " - convert it yourself, or ask for the type");
    }
}
