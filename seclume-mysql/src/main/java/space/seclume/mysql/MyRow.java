package space.seclume.mysql;

import java.lang.foreign.MemorySegment;
import java.util.List;

import space.seclume.internal.WireBuffer;

/**
 * A result row - a window onto the receive buffer, not a copy.
 *
 * <p>The same object serves all rows of a result: {@code start} moves the
 * window along. So there is no object per row and none per cell; whoever wants
 * to keep rows takes them over into a block of their own (see
 * {@code jdbc.MyResultBlock}) before the next packet is read.
 *
 * <p>MySQL has two row formats, and both end up here:
 *
 * <ul>
 *   <li><b>Text.</b> Every cell is a length-encoded string, {@code 0xfb} means
 *       NULL. Numbers arrive as digits too.</li>
 *   <li><b>Binary</b> (after {@code COM_STMT_EXECUTE}). One zero byte, then a
 *       bitmask for the NULL values, then the values in their respective binary
 *       form. The bitmask has two bits of lead-in - a historical offset that
 *       has already made more than one driver shift a column.</li>
 * </ul>
 */
public final class MyRow implements ValueCells {

    private final WireBuffer buffer;
    private final List<MySession.Field> fields;
    private final boolean binary;
    /** Two entries per cell: start within the buffer and length (-1 = NULL). */
    private final int[] cells;

    MyRow(WireBuffer buffer, List<MySession.Field> fields, boolean binary) {
        this.buffer = buffer;
        this.fields = fields;
        this.binary = binary;
        this.cells = new int[Math.max(fields.size(), 1) * 2];
    }

    /** Points the window at the row currently sitting in the buffer. */
    void start(int offset, int length) {
        if (binary) {
            scanBinary(offset, length);
        } else {
            scanText(offset, length);
        }
    }

    private void scanText(int offset, int length) {
        int at = offset;
        int end = offset + length;
        for (int column = 0; column < fields.size(); column++) {
            if (at >= end) {
                // Truncated rather than a bare IllegalStateException, and the
                // difference is the whole point: the session maps Truncated to
                // a connection failure, so this refusal reaches an application
                // as a SQLException instead of as an unchecked exception from
                // inside a decoder. The wording was already right; the type
                // was not. Found by the decoder fuzz sweep on 23.09.2026.
                throw space.seclume.internal.WireBuffer.Truncated.because(
                        "the row ended after " + column + " of " + fields.size() + " columns");
            }
            int first = buffer.getByte(at) & 0xff;
            int valueLength;
            int header;
            switch (first) {
                case 0xfb -> {
                    cells[column * 2] = at;
                    cells[column * 2 + 1] = -1;
                    at++;
                    continue;
                }
                case 0xfc -> {
                    header = 3;
                    valueLength = (int) unsigned(at + 1, 2);
                }
                case 0xfd -> {
                    header = 4;
                    valueLength = (int) unsigned(at + 1, 3);
                }
                case 0xfe -> {
                    header = 9;
                    valueLength = (int) unsigned(at + 1, 8);
                }
                default -> {
                    header = 1;
                    valueLength = first;
                }
            }
            cells[column * 2] = at + header;
            cells[column * 2 + 1] = valueLength;
            at += header + valueLength;
        }
    }

    private void scanBinary(int offset, int length) {
        int columns = fields.size();
        int nullBitmap = offset + 1;
        int bitmapLength = (columns + 9) / 8;
        int at = nullBitmap + bitmapLength;
        int end = offset + length;
        for (int column = 0; column < columns; column++) {
            // The two bits of lead-in: column 0 sits on bit 2 of the first byte.
            int bit = column + 2;
            int mask = buffer.getByte(nullBitmap + bit / 8) & 0xff;
            if ((mask & (1 << (bit % 8))) != 0) {
                cells[column * 2] = at;
                cells[column * 2 + 1] = -1;
                continue;
            }
            int type = fields.get(column).type();
            int fixed = MyTypes.binaryFixedLength(type);
            if (fixed > 0) {
                cells[column * 2] = at;
                cells[column * 2 + 1] = fixed;
                at += fixed;
            } else if (type == MyTypes.DATE || type == MyTypes.NEWDATE
                    || type == MyTypes.DATETIME || type == MyTypes.TIMESTAMP
                    || type == MyTypes.TIME) {
                // Time values carry their length in a byte in front.
                int valueLength = buffer.getByte(at) & 0xff;
                cells[column * 2] = at + 1;
                cells[column * 2 + 1] = valueLength;
                at += 1 + valueLength;
            } else {
                int first = buffer.getByte(at) & 0xff;
                int header;
                int valueLength;
                switch (first) {
                    case 0xfc -> {
                        header = 3;
                        valueLength = (int) unsigned(at + 1, 2);
                    }
                    case 0xfd -> {
                        header = 4;
                        valueLength = (int) unsigned(at + 1, 3);
                    }
                    case 0xfe -> {
                        header = 9;
                        valueLength = (int) unsigned(at + 1, 8);
                    }
                    default -> {
                        header = 1;
                        valueLength = first;
                    }
                }
                cells[column * 2] = at + header;
                cells[column * 2 + 1] = valueLength;
                at += header + valueLength;
            }
            if (at > end) {
                throw new IllegalStateException(
                        "column " + column + " runs past the end of the row");
            }
        }
    }

    private long unsigned(int at, int length) {
        long value = 0;
        for (int i = 0; i < length; i++) {
            value |= (buffer.getByte(at + i) & 0xffL) << (8 * i);
        }
        return value;
    }

    /** Whether the rows are binary encoded - reading the bytes hangs on it. */
    public boolean isBinary() {
        return binary;
    }

    @Override
    public List<MySession.Field> fields() {
        return fields;
    }

    public boolean isNull(int column) {
        return cells[column * 2 + 1] < 0;
    }

    /**
     * Where the row's bytes are - for whoever copies them out in one go.
     *
     * <p>Together with {@link #offset(int)} and {@link #length(int)} this is
     * the allocation-free way to take a row over. {@link #raw(int)} is the
     * comfortable one and cuts a slice per cell; at a thousand rows of three
     * columns that is three thousand objects.
     */
    public MemorySegment source() {
        return buffer.segment();
    }

    /** The raw bytes of a cell, without a copy; {@code null} for SQL NULL. */
    public MemorySegment raw(int column) {
        int length = cells[column * 2 + 1];
        return length < 0 ? null : buffer.slice(cells[column * 2], length);
    }

    @Override
    public int offset(int column) {
        return cells[column * 2];
    }

    @Override
    public int length(int column) {
        return cells[column * 2 + 1];
    }

    /**
     * The value as text.
     *
     * <p>Permissible for payload - that is what a driver is for. For secrets it
     * is the wrong way, but a secret coming out of the database is not what
     * this library protects against anyway.
     */
    public String getString(int column) {
        int length = cells[column * 2 + 1];
        if (length < 0) {
            return null;
        }
        if (binary) {
            return BinaryValues.toText(this, column);
        }
        int saved = buffer.position();
        int savedLimit = buffer.limit();
        try {
            buffer.position(cells[column * 2]);
            buffer.limit(cells[column * 2] + length);
            return buffer.readString(length);
        } finally {
            buffer.position(saved);
            buffer.limit(savedLimit);
        }
    }

    /** The number without the detour through a {@code String}. */
    public long getLong(int column) {
        int length = cells[column * 2 + 1];
        if (length < 0) {
            return 0;
        }
        int at = cells[column * 2];
        if (binary) {
            return BinaryValues.toLong(this, column);
        }
        return parseDigits(at, length);
    }

    private long parseDigits(int at, int length) {
        boolean negative = length > 0 && buffer.getByte(at) == '-';
        long value = 0;
        for (int i = negative ? 1 : 0; i < length; i++) {
            byte digit = buffer.getByte(at + i);
            if (digit < '0' || digit > '9') {
                throw new NumberFormatException(
                        "the value is not a whole number - use getString or getBigDecimal");
            }
            value = value * 10 + (digit - '0');
        }
        return negative ? -value : value;
    }

    public boolean getBoolean(int column) {
        if (isNull(column)) {
            return false;
        }
        // MySQL has no bool; tinyint(1) is the convention, and everything
        // other than 0 counts as true.
        return getLong(column) != 0;
    }

    @Override
    public byte byteAt(int at) {
        return buffer.getByte(at);
    }

    @Override
    public long decimalAt(int at, int length) {
        return space.seclume.internal.jdbc.TextNumber.decimal(buffer, at, length);
    }

    @Override
    public long unsignedAt(int at, int length) {
        return unsigned(at, length);
    }

    @Override
    public String textAt(int at, int length) {
        int saved = buffer.position();
        int savedLimit = buffer.limit();
        try {
            buffer.position(at);
            buffer.limit(at + length);
            return buffer.readString(length);
        } finally {
            buffer.position(saved);
            buffer.limit(savedLimit);
        }
    }
}
