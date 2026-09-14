package space.seclume.postgresql;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.List;

import space.seclume.internal.WireBuffer;

/**
 * A result row - as a window onto the receive buffer, not as a copy.
 *
 * <p>This is the place where a driver loses its time under load. The usual way
 * creates a {@code byte[]} per cell and a {@code String} out of it; at 10,000
 * rows with ten columns that is 200,000 objects for a single query, all of
 * which the GC has to collect again. Here the row only points at the bytes that
 * are already sitting in the buffer anyway. A Java object only comes into being
 * when the caller actually fetches the column - and with {@link #getLong(int)}
 * none at all.
 *
 * <p><b>Only valid during the callback.</b> Afterwards the buffer is free
 * again; whoever wants to keep a row has to copy its values. That is the price
 * for the speed, and it stands here so that nobody overlooks it.
 *
 * <p>Because of that contract the object itself is <b>reused</b>: one instance
 * per session, refilled for every row. A new one per row would be three
 * allocations - the window and its two index arrays - and at a thousand rows
 * that is three thousand objects for a result the caller reads once.
 */
public final class Row {

    private WireBuffer buffer;
    private List<PgSession.Field> fields;
    private int[] offsets;
    private int[] lengths;
    private int count;

    Row(WireBuffer buffer, List<PgSession.Field> fields, int[] offsets, int[] lengths) {
        reset(buffer, fields, offsets, lengths, offsets.length);
    }

    /**
     * Points the window at the next row. The arrays belong to the session and
     * may be longer than this row is wide, so the width is passed separately.
     */
    void reset(WireBuffer buffer, List<PgSession.Field> fields, int[] offsets,
               int[] lengths, int count) {
        this.buffer = buffer;
        this.fields = fields;
        this.offsets = offsets;
        this.lengths = lengths;
        this.count = count;
    }

    public int columnCount() {
        return count;
    }

    public List<PgSession.Field> fields() {
        return fields;
    }

    public boolean isNull(int column) {
        return lengths[column] < 0;
    }

    /**
     * Where the row's bytes are - for whoever copies them out in one go.
     *
     * <p>Together with {@link #offset(int)} and {@link #length(int)} this is
     * the allocation-free way to take a row over. {@link #raw(int)} is the
     * comfortable one and cuts a slice per cell; at a thousand rows of three
     * columns that is three thousand objects, and it showed up as eleven
     * percent in the benchmark against pgjdbc.
     */
    public MemorySegment source() {
        return buffer.segment();
    }

    /** Where the column starts in {@link #source()}. */
    public int offset(int column) {
        return offsets[column];
    }

    /** How long the column is; negative for SQL NULL. */
    public int length(int column) {
        return lengths[column];
    }

    /** The raw bytes of the column, without a copy; {@code null} for SQL NULL. */
    public MemorySegment raw(int column) {
        if (isNull(column)) {
            return null;
        }
        return buffer.slice(offsets[column], lengths[column]);
    }

    /** The column as text. Here a {@code String} deliberately comes into being. */
    public String getString(int column) {
        if (isNull(column)) {
            return null;
        }
        byte[] bytes = new byte[lengths[column]]; // seclume-allow: user payload requested as text, not a secret
        MemorySegment.copy(buffer.segment(), ValueLayout.JAVA_BYTE, offsets[column],
                bytes, 0, bytes.length);
        return new String(bytes, StandardCharsets.UTF_8); // seclume-allow: user payload requested as text, not a secret
    }

    /**
     * The column as an integer, straight from the bytes of the text format -
     * without a {@code String} and without {@code Long.parseLong}.
     */
    public long getLong(int column) {
        if (isNull(column)) {
            return 0;
        }
        int offset = offsets[column];
        int length = lengths[column];
        boolean negative = false;
        int i = 0;
        if (length > 0 && buffer.getByte(offset) == '-') {
            negative = true;
            i = 1;
        }
        long value = 0;
        for (; i < length; i++) {
            int digit = (buffer.getByte(offset + i) & 0xff) - '0';
            if (digit < 0 || digit > 9) {
                throw new NumberFormatException(
                        "column " + column + " is not an integer in text format");
            }
            value = value * 10 + digit;
        }
        return negative ? -value : value;
    }

    public int getInt(int column) {
        return (int) getLong(column);
    }

    public boolean getBoolean(int column) {
        if (isNull(column)) {
            return false;
        }
        // In the text format PostgreSQL writes "t" and "f".
        return buffer.getByte(offsets[column]) == 't';
    }
}
