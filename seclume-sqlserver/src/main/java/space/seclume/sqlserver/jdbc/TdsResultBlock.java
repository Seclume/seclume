package space.seclume.sqlserver.jdbc;

import java.util.Arrays;
import java.util.List;

import space.seclume.internal.WireBuffer;
import space.seclume.sqlserver.tds.TdsColumn;
import space.seclume.sqlserver.tds.TdsRow;

/**
 * The rows of a result, buffered - but off-heap.
 *
 * <p>A {@code ResultSet} has to survive the statement that produced it; a
 * window onto the receive buffer does not. The usual way out is an
 * {@code Object[]} per row with a {@code String} per cell - at 10,000 rows of
 * ten columns that is 110,000 objects for the garbage collector, and the
 * values sit on the heap whether anyone reads them or not.
 *
 * <p>Here the bytes go into a single native block, plus an {@code int} array
 * with the start and length of every cell. A Java object only comes into being
 * when somebody asks for one - and {@code getLong} never asks.
 *
 * <p>The bytes keep the form the server sent them in. A {@code datetime2} is
 * seven bytes here, not a {@code String}; the conversion happens on access and
 * only for what is accessed.

 *
 * <p>The block belongs to the statement and is <b>reused</b> for every
 * execution rather than built anew: a fresh one means a native allocation and
 * a free per statement, which a benchmark showed to be a third of the time of
 * a small query. JDBC allows it - re-executing a statement invalidates the
 * previous {@code ResultSet} anyway.
 */
final class TdsResultBlock implements AutoCloseable {

    private List<TdsColumn> columns;
    private int columnCount;
    private final WireBuffer data;
    /** Two entries per cell: start within the block and length (-1 = SQL NULL). */
    private int[] cells;
    private int rowCount;
    /** The row the accessors refer to. */
    private int current;

    TdsResultBlock(List<TdsColumn> columns) {
        this.data = new WireBuffer(8 * 1024);
        this.cells = new int[0];
        reset(columns);
    }

    /**
     * Takes the block over for the next result: same memory, new columns.
     *
     * <p>The bytes of the previous result are not wiped - they are payload,
     * not a secret, and the new rows overwrite them. What has to be right is
     * the position, and that is what {@code clear} sets.
     */
    void reset(List<TdsColumn> columns) {
        this.columns = columns;
        this.columnCount = columns.size();
        this.rowCount = 0;
        this.current = 0;
        this.data.clear();
        int needed = Math.max(columnCount, 1) * 2 * 64;
        if (cells.length < needed) {
            cells = new int[needed];
        }
    }

    /** Takes a row over from the receive buffer. */
    void append(TdsRow row) {
        int needed = (rowCount + 1) * columnCount * 2;
        if (needed > cells.length) {
            cells = Arrays.copyOf(cells, Math.max(needed, cells.length * 2));
        }
        for (int column = 0; column < columnCount; column++) {
            int index = (rowCount * columnCount + column) * 2;
            if (row.isNull(column)) {
                cells[index] = 0;
                cells[index + 1] = -1;
                continue;
            }
            int length = row.cellLength(column);
            data.ensureCapacity(data.position() + length);
            cells[index] = data.position();
            cells[index + 1] = length;
            row.copyTo(column, data);
        }
        rowCount++;
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
        return columnCount;
    }

    List<TdsColumn> columns() {
        return columns;
    }

    TdsColumn column(int index) {
        return columns.get(index);
    }

    /** Selects the row the accessors refer to. */
    void select(int row) {
        this.current = row;
    }

    /** The buffer the values live in - the readers work straight on it. */
    WireBuffer data() {
        return data;
    }

    int offset(int column) {
        return cells[(current * columnCount + column) * 2];
    }

    int length(int column) {
        return cells[(current * columnCount + column) * 2 + 1];
    }

    boolean isNull(int column) {
        return length(column) < 0;
    }

    @Override
    public void close() {
        data.close();
        Arrays.fill(cells, 0);
        rowCount = 0;
    }
}
