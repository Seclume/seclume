package space.seclume.mysql.jdbc;

import java.util.Arrays;
import java.util.List;

import space.seclume.internal.WireBuffer;
import space.seclume.mysql.MyRow;
import space.seclume.mysql.MySession;
import space.seclume.mysql.ValueCells;

/**
 * The rows of a result, buffered - but off-heap.
 *
 * <p>A {@code ResultSet} has to survive the query; the window onto the receive
 * buffer is not enough for that. The usual way out is an {@code Object[]} per
 * row with a {@code String} per cell - at 10,000 rows of ten columns that is
 * 110,000 objects for the garbage collector.
 *
 * <p>Here the raw bytes land in a single native block, plus an {@code int}
 * array with the start and length of every cell. A Java object only comes into
 * being when somebody calls {@code getString} - and with {@code getLong} none
 * at all.
 *
 * <p>The bytes keep their format along the way: rows from the text protocol
 * stay text, rows from {@code COM_STMT_EXECUTE} stay binary. Conversion only
 * happens on access, and only for what is accessed.

 *
 * <p>The block belongs to the statement and is <b>reused</b> for every
 * execution rather than built anew: a fresh one means a native allocation and
 * a free per statement, which a benchmark showed to be a third of the time of
 * a small query. JDBC allows it - re-executing a statement invalidates the
 * previous {@code ResultSet} anyway.
 */
final class MyResultBlock implements ValueCells, AutoCloseable {

    private List<MySession.Field> fields;
    private int columns;
    private boolean binary;
    private final WireBuffer data;
    /** Reused by the BigDecimal path, which reads a char[] instead of a String. */
    private char[] characters = new char[64]; // seclume-allow: user payload on its way to a number, not a secret
    /** Two entries per cell: start within the block and length (-1 = SQL NULL). */
    private int[] cells;
    private int rowCount;
    /** The row {@link ValueCells} currently refers to. */
    private int current;

    private final boolean tinyInt1isBit;

    /** Whether a tinyint(1) in this result is a boolean. */
    boolean tinyInt1isBit() {
        return tinyInt1isBit;
    }

    MyResultBlock(List<MySession.Field> fields, boolean binary, boolean tinyInt1isBit) {
        this.tinyInt1isBit = tinyInt1isBit;
        this.data = new WireBuffer(8 * 1024);
        this.cells = new int[0];
        reset(fields, binary);
    }

    /**
     * Takes the block over for the next result: same memory, new columns.
     *
     * <p>The bytes of the previous result are not wiped - they are payload,
     * not a secret, and the new rows overwrite them. What has to be right is
     * the position, and that is what {@code clear} sets.
     */
    void reset(List<MySession.Field> fields, boolean binary) {
        this.fields = fields;
        this.columns = fields.size();
        this.binary = binary;
        this.rowCount = 0;
        this.current = 0;
        this.data.clear();
        int needed = Math.max(columns, 1) * 2 * 64;
        if (cells.length < needed) {
            cells = new int[needed];
        }
    }

    /** Takes a row over from the receive buffer. */
    void append(MyRow row) {
        int needed = (rowCount + 1) * columns * 2;
        if (needed > cells.length) {
            cells = Arrays.copyOf(cells, Math.max(needed, cells.length * 2));
        }
        // One copy for the whole row, not one per cell.
        //
        // The cells lie next to each other in the receive buffer, separated
        // only by their length prefixes. Copying the span in one go takes
        // those bytes along as filler - a few bytes of memory for one memory
        // copy per row instead of one per column.
        java.lang.foreign.MemorySegment source = row.source();
        int from = -1;
        int to = -1;
        for (int column = 0; column < columns; column++) {
            int length = row.length(column);
            if (length < 0) {
                continue;
            }
            if (from < 0) {
                from = row.offset(column);
            }
            to = row.offset(column) + length;
        }
        int base = data.position();
        if (from >= 0) {
            data.putBytes(source, from, to - from);
        }
        for (int column = 0; column < columns; column++) {
            int index = (rowCount * columns + column) * 2;
            int length = row.length(column);
            if (length < 0) {
                cells[index] = 0;
                cells[index + 1] = -1;
                continue;
            }
            cells[index] = base + (row.offset(column) - from);
            cells[index + 1] = length;
        }
        rowCount++;
    }


    /** The buffer the rows live in - for the native window, see Sensitive. */
    WireBuffer data() {
        return data;
    }

    /**
     * How many bytes of row data are in here.
     *
     * <p>The buffer's own position - the rows were copied into it, so nothing
     * has to be counted a second time.
     */
    long bytes() {
        return data.position();
    }

    int rowCount() {
        return rowCount;
    }

    int columnCount() {
        return columns;
    }

    boolean isBinary() {
        return binary;
    }

    /** Selects the row the cell accessors refer to. */
    void select(int row) {
        this.current = row;
    }

    boolean isNull(int row, int column) {
        return cells[(row * columns + column) * 2 + 1] < 0;
    }

    // ---- ValueCells ------------------------------------------------------

    @Override
    public List<MySession.Field> fields() {
        return fields;
    }

    @Override
    public int offset(int column) {
        return cells[(current * columns + column) * 2];
    }

    @Override
    public int length(int column) {
        return cells[(current * columns + column) * 2 + 1];
    }

    @Override
    public byte byteAt(int at) {
        return data.getByte(at);
    }

    @Override
    public long decimalAt(int at, int length) {
        return space.seclume.internal.jdbc.TextNumber.decimal(data, at, length);
    }

    /** A double straight from the digits - see {@code TextNumber}. */
    double decimalDoubleAt(int at, int length) {
        return space.seclume.internal.jdbc.TextNumber.decimalDouble(data, at, length);
    }

    /** A BigDecimal out of a reused char[] rather than a fresh String. */
    java.math.BigDecimal bigDecimalAt(int at, int length) {
        if (characters.length < length) {
            characters = new char[Math.max(length, characters.length * 2)]; // seclume-allow: user payload on its way to a number, not a secret
        }
        return space.seclume.internal.jdbc.TextNumber.bigDecimal(data, at, length, characters);
    }

    @Override
    public long unsignedAt(int at, int length) {
        long value = 0;
        for (int i = 0; i < length; i++) {
            value |= (data.getByte(at + i) & 0xffL) << (8 * i);
        }
        return value;
    }

    @Override
    public String textAt(int at, int length) {
        int savedPosition = data.position();
        int savedLimit = data.limit();
        try {
            data.position(at);
            data.limit(at + length);
            return data.readString(length);
        } finally {
            data.position(savedPosition);
            data.limit(savedLimit);
        }
    }

    @Override
    public void close() {
        data.close();
        Arrays.fill(cells, 0);
        rowCount = 0;
    }
}
