package space.seclume.postgresql;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.sql.Time;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.UUID;

import space.seclume.internal.WireBuffer;

/**
 * The parameters of a prepared statement.
 *
 * <p>They are written in the text format. That is deliberately the first step:
 * it covers every type the server knows without the driver having to bring a
 * binary representation for each single one - and what it does not speak it
 * cannot encode wrongly either. The binary format is added type by type where
 * it pays off, and is noted in {@code PROVENANCE.md} as an open
 * point.
 *
 * <p>No value is built into the SQL text. Parameters go over the wire as
 * parameters, and with that there is no SQL injection - not as an intention,
 * but by construction.
 */
public final class PgParameters {

    /** Format tag: 0 = text, 1 = binary. */
    static final short TEXT_FORMAT = 0;

    private Object[] values;
    private int count;

    public PgParameters(int expected) {
        this.values = new Object[Math.max(expected, 8)];
    }

    /** The number of parameters set; the gaps in between are NULL. */
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

    /** Writes the values into the Bind message. */
    void write(WireBuffer out) {
        // All parameters in the same format - one format tag is enough.
        out.putShort((short) 1);
        out.putShort(TEXT_FORMAT);
        out.putShort((short) count);
        for (int i = 0; i < count; i++) {
            Object value = values[i];
            if (value == null) {
                out.putInt(-1);
                continue;
            }
            byte[] text = encode(value); // seclume-allow: user payload, not a database password
            out.putInt(text.length);
            out.putBytes(java.lang.foreign.MemorySegment.ofArray(text), 0, text.length);
        }
    }

    /**
     * The text representation PostgreSQL expects for this type.
     *
     * <p>Not {@code toString()}: {@code Boolean.toString()} yields "true", the
     * server wants "t"; {@code byte[]} needs the hex form; and
     * {@code BigDecimal.toString()} can slip into exponential notation, which
     * the server does accept as a number but rounds differently.
     */
    private static byte[] encode(Object value) {
        String text;
        if (value instanceof byte[] bytes) {
            return hexBytea(bytes);
        } else if (value instanceof Boolean flag) {
            text = flag ? "t" : "f";
        } else if (value instanceof BigDecimal decimal) {
            text = decimal.toPlainString();
        } else if (value instanceof Timestamp timestamp) {
            text = timestamp.toLocalDateTime().toString().replace('T', ' ');
        } else if (value instanceof Date date) {
            text = date.toLocalDate().toString();
        } else if (value instanceof Time time) {
            text = time.toLocalTime().toString();
        } else if (value instanceof LocalDateTime dateTime) {
            text = dateTime.toString().replace('T', ' ');
        } else if (value instanceof OffsetDateTime dateTime) {
            text = dateTime.toString().replace('T', ' ');
        } else if (value instanceof LocalDate date) {
            text = date.toString();
        } else if (value instanceof LocalTime time) {
            text = time.toString();
        } else if (value instanceof UUID uuid) {
            text = uuid.toString();
        } else if (value instanceof Number || value instanceof CharSequence
                || value instanceof Character) {
            text = value.toString();
        } else {
            throw new IllegalArgumentException(
                    "seclume does not know how to send a " + value.getClass().getName()
                    + " - convert it yourself, or ask for the type");
        }
        return text.getBytes(StandardCharsets.UTF_8); // seclume-allow: user payload, not a database password
    }

    /** {@code bytea} in hex format: {@code \x} and then two chars per byte. */
    private static byte[] hexBytea(byte[] bytes) {
        byte[] out = new byte[2 + bytes.length * 2];
        out[0] = '\\';
        out[1] = 'x';
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            out[2 + i * 2] = hexDigit(value >>> 4);
            out[3 + i * 2] = hexDigit(value & 0x0f);
        }
        return out;
    }

    private static byte hexDigit(int value) {
        return (byte) (value < 10 ? '0' + value : 'a' + value - 10);
    }
}
