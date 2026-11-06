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
                throw WireBuffer.Truncated.because(
                        "the row ended after " + column + " of " + fields.size() + " columns");
            }
            if ((buffer.getByte(at) & 0xff) == 0xfb) {
                cells[column * 2] = at;
                cells[column * 2 + 1] = -1;
                at++;
                continue;
            }
            at = lengthEncoded(column, at, end);
        }
    }

    private void scanBinary(int offset, int length) {
        int columns = fields.size();
        int nullBitmap = offset + 1;
        int bitmapLength = (columns + 9) / 8;
        int at = nullBitmap + bitmapLength;
        int end = offset + length;
        if (at > end) {
            throw WireBuffer.Truncated.because("a binary row of " + length + " bytes, where "
                    + "its header and NULL bitmap for " + columns + " columns take "
                    + (1 + bitmapLength));
        }
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
                cell(column, at, fixed, end);
                at += fixed;
            } else if (type == MyTypes.DATE || type == MyTypes.NEWDATE
                    || type == MyTypes.DATETIME || type == MyTypes.TIMESTAMP
                    || type == MyTypes.TIME) {
                // Time values carry their length in a byte in front.
                if (at >= end) {
                    throw beyond(column, 1, end - at);
                }
                int valueLength = buffer.getByte(at) & 0xff;
                cell(column, at + 1, valueLength, end);
                at += 1 + valueLength;
            } else {
                at = lengthEncoded(column, at, end);
            }
        }
    }

    /**
     * Reads the length-encoded cell at {@code at} - one byte under 0xfb, or
     * 0xfc, 0xfd, 0xfe and two, three or eight bytes of length - and returns
     * where the next one starts. A length that does not fit in what is left of
     * the row is refused: the bytes after the row belong to the next packet,
     * and an eight-byte length cut down to an int could come out negative and
     * read as NULL, or small and read as a value.
     */
    private int lengthEncoded(int column, int at, int end) {
        int first = buffer.getByte(at) & 0xff;
        int header = switch (first) {
            case 0xfc -> 3;
            case 0xfd -> 4;
            case 0xfe -> 9;
            default -> 1;
        };
        if (end - at < header) {
            throw beyond(column, header, end - at);
        }
        long valueLength = header == 1 ? first : unsigned(at + 1, header - 1);
        if (valueLength < 0 || valueLength > end - at - header) {
            throw WireBuffer.Truncated.because("column " + (column + 1) + " of "
                    + fields.size() + " says " + Long.toUnsignedString(valueLength)
                    + " bytes, and the row has " + (end - at - header) + " left");
        }
        cells[column * 2] = at + header;
        cells[column * 2 + 1] = (int) valueLength;
        return at + header + (int) valueLength;
    }

    private void cell(int column, int at, int valueLength, int end) {
        if (valueLength > end - at) {
            throw beyond(column, valueLength, end - at);
        }
        cells[column * 2] = at;
        cells[column * 2 + 1] = valueLength;
    }

    private WireBuffer.Truncated beyond(int column, int needed, int left) {
        return WireBuffer.Truncated.because("column " + (column + 1) + " of " + fields.size()
                + " needs " + needed + " bytes, and the row has " + left + " left");
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
