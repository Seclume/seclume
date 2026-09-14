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

    /** Sets the parameter with a 1-based index, the way JDBC counts. */
    public void set(int index, Object value) {
        if (index < 1) {
            throw new IllegalArgumentException("parameter indexes start at 1, got " + index);
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
        if (value instanceof byte[]) {
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
        if (value instanceof byte[] bytes) {
            MyPackets.writeLengthEncoded(out, bytes.length);
            out.putBytes(MemorySegment.ofArray(bytes), 0, bytes.length);
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
        if (value instanceof UUID uuid) {
            return uuid.toString();
        }
        if (value instanceof Number || value instanceof CharSequence
                || value instanceof Character) {
            return value.toString();
        }
        throw new IllegalArgumentException(
                "seclume does not know how to send a " + value.getClass().getName()
                + " - convert it yourself, or open the type in docs/protocol/mysql.md");
    }
}
