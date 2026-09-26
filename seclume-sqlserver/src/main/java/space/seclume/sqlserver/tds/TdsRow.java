package space.seclume.sqlserver.tds;

import java.io.IOException;
import java.util.List;

import space.seclume.internal.WireBuffer;

/**
 * A result row - a window onto the message buffer, not a copy.
 *
 * <p>The same object serves every row of a result: {@link #read} moves the
 * window along. So there is no object per row and none per cell; whoever wants
 * to keep a row copies its values before the next message is read.
 *
 * <p>TDS has two row tokens and they differ in one thing only:
 *
 * <ul>
 *   <li><b>{@code ROW}.</b> Every column carries its value, and a NULL is a
 *       length of zero or {@code 0xffff}, depending on the framing.</li>
 *   <li><b>{@code NBCROW}.</b> A bitmask up front says which columns are NULL,
 *       and those carry no bytes at all. On a wide table with many NULLs that
 *       saves a good part of the row - and it is the shape a driver has to be
 *       able to read, because the server decides which one it sends.</li>
 * </ul>
 *
 * <p>The value framing is the part that has to be exact: fixed-length types
 * carry no length at all, most variable ones a single byte, the {@code BIG…}
 * and {@code N…} family two, {@code text}/{@code image} four with a text
 * pointer in front, and a {@code MAX} column arrives in chunks. One misread
 * length shifts every following column - and produces plausible nonsense
 * rather than an error, which is worse.
 */
public final class TdsRow {

    /** A two-byte length of {@code 0xffff} means NULL. */
    private static final int NULL_TWO_BYTE = 0xffff;
    /** A PLP total length of all ones means NULL. */
    private static final long PLP_NULL = 0xffffffffffffffffL;
    /** A PLP total length of all ones but the last bit means "unknown". */
    private static final long PLP_UNKNOWN = 0xfffffffffffffffeL;

    private final WireBuffer in;
    private final List<TdsColumn> columns;
    /** Two entries per cell: start within the buffer and length (-1 = NULL). */
    private final int[] cells;
    /** Where the row ends - the caller carries on from here. */
    private int end;

    public TdsRow(WireBuffer in, List<TdsColumn> columns) {
        this.in = in;
        this.columns = columns;
        this.cells = new int[columns.size() * 2]; // seclume-allow: offsets into the buffer, not content
        this.hasPlp = columns.stream().anyMatch(TdsColumn::plp);
    }

    /**
     * Points the window at the row that starts at {@code at}.
     *
     * @param at              the position just after the row token
     * @param nullBitCompressed whether this is an {@code NBCROW}
     * @return the position just after the row
     */
    public int read(int at, boolean nullBitCompressed) throws IOException {
        if (hasPlp) {
            // A MAX value is made contiguous by moving its chunks, in place.
            // The answer is read while it arrives, and a row cut by the end of
            // a packet is read again from its start once the rest is in - so
            // nothing may move until the whole row is known to be there: one
            // pass that only measures, and checks the last byte.
            measuring = true;
            try {
                int end = pass(at, nullBitCompressed);
                if (end > at) {
                    in.getByte(end - 1);                   // there, or Truncated
                }
            } finally {
                measuring = false;
            }
        }
        return pass(at, nullBitCompressed);
    }

    /** Whether this pass only finds where the row ends; see {@link #read}. */
    private boolean measuring;
    /** Whether any column arrives chunked. */
    private final boolean hasPlp;

    private int pass(int at, boolean nullBitCompressed) throws IOException {
        int p = at;
        int count = columns.size();
        int bitmaskAt = -1;
        if (nullBitCompressed) {
            bitmaskAt = p;
            p += (count + 7) / 8;
        }
        for (int i = 0; i < count; i++) {
            if (bitmaskAt >= 0 && isNullBitSet(bitmaskAt, i)) {
                cells[i * 2] = p;
                cells[i * 2 + 1] = -1;
                continue;
            }
            p = readCell(i, p);
        }
        end = p;
        return p;
    }

    /** Where the row ended - only valid after {@link #read}. */
    public int end() {
        return end;
    }

    /**
     * Reads one value's framing and records where it sits.
     *
     * <p>Nothing is copied here: the cell entry is a pair of offsets into the
     * message buffer, and the bytes stay where the channel put them.
     */
    private int readCell(int index, int at) throws IOException {
        TdsColumn column = columns.get(index);
        int type = column.type();
        int p = at;

        int fixed = TdsTypes.fixedLength(type);
        if (fixed >= 0) {
            set(index, p, fixed);
            return p + fixed;
        }
        if (column.plp()) {
            return readPlp(index, p);
        }
        if (type == TdsTypes.SQLVARIANT) {
            // Four bytes of length, and zero means NULL - there is no text
            // pointer here, which is why this cannot share the branch below.
            // The cell keeps its base type and property bytes; TdsValues
            // unwraps them, because only the value knows what it is.
            int length = in.getIntLe(p);
            p += 4;
            if (length == 0) {
                set(index, p, -1);
                return p;
            }
            set(index, p, length);
            return p + length;
        }
        if (TdsTypes.hasFourByteLength(type)) {
            int pointerLength = in.getByte(p) & 0xff;
            p++;
            if (pointerLength == 0) {
                set(index, p, -1);
                return p;
            }
            p += pointerLength + 8;                  // text pointer and timestamp
            int length = in.getIntLe(p);
            p += 4;
            set(index, p, length);
            return p + length;
        }
        if (TdsTypes.hasTwoByteLength(type)) {
            int length = (in.getByte(p) & 0xff) | ((in.getByte(p + 1) & 0xff) << 8);
            p += 2;
            if (length == NULL_TWO_BYTE) {
                set(index, p, -1);
                return p;
            }
            set(index, p, length);
            return p + length;
        }
        int length = in.getByte(p) & 0xff;
        p++;
        if (length == 0) {
            // For every one-byte type a length of zero is the NULL - an empty
            // string arrives from the server as a BIG… type with length 0 and
            // is therefore never confused with this.
            set(index, p, -1);
            return p;
        }
        set(index, p, length);
        return p + length;
    }

    /**
     * A {@code MAX} column: an eight-byte total length, then chunks with a
     * four-byte length each until a chunk of zero.
     *
     * <p>The chunks are moved together in the buffer so that the value ends up
     * contiguous - the alternative would be a list of pieces that every reader
     * would have to know about. Moving happens in place and only backwards,
     * over bytes that have already been consumed.
     */
    private int readPlp(int index, int at) throws IOException {
        long total = 0;
        for (int i = 7; i >= 0; i--) {
            total = (total << 8) | (in.getByte(at + i) & 0xffL);
        }
        int p = at + 8;
        if (total == PLP_NULL) {
            set(index, p, -1);
            return p;
        }
        if (total != PLP_UNKNOWN && total > Integer.MAX_VALUE) {
            throw new IOException("a value of " + total + " bytes does not fit into a row");
        }
        if (measuring) {
            // Only where it ends - see read: nothing moves until the whole
            // row is known to be there.
            for (int q = p; ; ) {
                int chunk = in.getIntLe(q);
                q += 4;
                if (chunk == 0) {
                    return q;
                }
                if (chunk < 0) {
                    throw new IOException("a chunk of " + chunk + " bytes");
                }
                in.getByte(q + chunk - 1);             // there, or Truncated
                q += chunk;
            }
        }
        int valueAt = p;
        int written = 0;
        while (true) {
            int chunk = in.getIntLe(p);
            p += 4;
            if (chunk == 0) {
                break;
            }
            // The chunk starts at p, its place in the value at valueAt+written.
            // Those differ from the first chunk onwards, because the chunk
            // lengths sit between them - so this moves nearly always, and
            // always backwards over bytes that are already read.
            if (valueAt + written != p) {
                java.lang.foreign.MemorySegment.copy(in.segment(), p,
                        in.segment(), valueAt + written, chunk);
            }
            written += chunk;
            p += chunk;
        }
        set(index, valueAt, written);
        return p;
    }

    private boolean isNullBitSet(int bitmaskAt, int column) {
        int mask = in.getByte(bitmaskAt + column / 8) & 0xff;
        return (mask & (1 << (column % 8))) != 0;
    }

    private void set(int index, int at, int length) {
        cells[index * 2] = at;
        cells[index * 2 + 1] = length;
    }

    // ---- reading the values ----------------------------------------------

    public int columnCount() {
        return columns.size();
    }

    public TdsColumn column(int index) {
        return columns.get(index);
    }

    /** The description this row belongs to. */
    public List<TdsColumn> columns() {
        return columns;
    }

    public boolean isNull(int index) {
        return cells[index * 2 + 1] < 0;
    }

    /** The raw bytes of a cell; {@code null} for SQL NULL. */
    public byte[] bytes(int index) {
        if (isNull(index)) {
            return null;
        }
        return TdsValues.asBytes(in, cells[index * 2], cells[index * 2 + 1]);
    }

    /** The value as text; {@code null} for SQL NULL. */
    public String text(int index) {
        if (isNull(index)) {
            return null;
        }
        TdsColumn column = columns.get(index);
        return TdsValues.asText(in, column.type(), cells[index * 2], cells[index * 2 + 1],
                column.scale());
    }

    /** The value as an integer; 0 for SQL NULL, as JDBC prescribes. */
    public long number(int index) {
        if (isNull(index)) {
            return 0;
        }
        return TdsValues.asLong(in, columns.get(index).type(),
                cells[index * 2], cells[index * 2 + 1]);
    }

    /** The value as a floating-point number; 0 for SQL NULL. */
    public double decimal(int index) {
        if (isNull(index)) {
            return 0;
        }
        return TdsValues.asDouble(in, columns.get(index).type(),
                cells[index * 2], cells[index * 2 + 1]);
    }

    /** The value as a truth value; {@code false} for SQL NULL. */
    public boolean flag(int index) {
        if (isNull(index)) {
            return false;
        }
        return TdsValues.asBoolean(in, columns.get(index).type(),
                cells[index * 2], cells[index * 2 + 1]);
    }

    /**
     * Copies a cell into another buffer, at its current position.
     *
     * <p>This is how a {@code ResultSet} takes a row over: the row itself is
     * only a window and is gone with the next message, so whoever wants to keep
     * it moves the bytes - straight from native memory to native memory,
     * without a Java object in between.
     */
    public void copyTo(int index, WireBuffer target) {
        int length = cells[index * 2 + 1];
        if (length > 0) {
            target.putBytes(in.segment(), cells[index * 2], length);
        }
    }

    /**
     * The memory every cell of this row points into.
     *
     * <p>One buffer for the whole row, which is what lets a reader take the
     * row over in a single copy. It holds even for a partially length
     * prefixed value: those arrive in chunks and are compacted <b>in place</b>
     * in this same buffer - see {@code readPlp}.
     */
    public java.lang.foreign.MemorySegment source() {
        return in.segment();
    }

    /** Where a cell sits in the buffer - for whoever takes the row over. */
    public int cellAt(int index) {
        return cells[index * 2];
    }

    /** How long a cell is; negative for SQL NULL. */
    public int cellLength(int index) {
        return cells[index * 2 + 1];
    }
}
