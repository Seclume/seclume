package space.seclume.oracle.jdbc;

import java.util.Arrays;
import java.util.List;

import space.seclume.internal.WireBuffer;
import space.seclume.oracle.net.OracleColumn;
import space.seclume.oracle.net.TtcRow;

/**
 * The rows of a result, buffered - but off-heap.
 *
 * <p>A {@code ResultSet} has to survive the statement; a window onto the
 * receive buffer does not. The bytes therefore go into a single native block
 * plus an {@code int} array with the start and length of every cell. A Java
 * object only comes into being when somebody asks for one - and
 * {@code getLong} never asks.
 *
 * <p>The values keep the form the server sent them in: a number stays Oracle's
 * base-100 format until somebody reads it.

 *
 * <p>The block belongs to the statement and is <b>reused</b> for every
 * execution rather than built anew: a fresh one means a native allocation and
 * a free per statement, which a benchmark showed to be a third of the time of
 * a small query. JDBC allows it - re-executing a statement invalidates the
 * previous {@code ResultSet} anyway.
 */
final class OraResultBlock implements AutoCloseable {

    private List<OracleColumn> columns;
    private int columnCount;
    private final WireBuffer data;
    /** Two entries per cell: start within the block and length (-1 = NULL). */
    private int[] cells;
    /** One per cell: how long the LOB is, straight out of the row. */
    private long[] lobLengths;
    private int rowCount;
    private int current;

    OraResultBlock(List<OracleColumn> columns) {
        this.data = new WireBuffer(8 * 1024);
        this.cells = new int[0];
        this.lobLengths = new long[0];
        reset(columns);
    }

    /**
     * Takes the block over for the next result: same memory, new columns.
     *
     * <p>The bytes of the previous result are not wiped - they are payload,
     * not a secret, and the new rows overwrite them. What has to be right is
     * the position, and that is what {@code clear} sets.
     */
    void reset(List<OracleColumn> columns) {
        this.columns = columns;
        this.columnCount = columns.size();
        this.rowCount = 0;
        this.current = 0;
        this.data.clear();
        int needed = Math.max(columnCount, 1) * 2 * 64;
        if (cells.length < needed) {
            cells = new int[needed];
        }
        if (lobLengths.length < needed / 2) {
            lobLengths = new long[needed / 2];
        }
    }

    /** Takes a row over from the receive buffer. */
    void append(TtcRow row) {
        int needed = (rowCount + 1) * columnCount * 2;
        if (needed > cells.length) {
            cells = Arrays.copyOf(cells, Math.max(needed, cells.length * 2));
        }
        if (needed / 2 > lobLengths.length) {
            lobLengths = Arrays.copyOf(lobLengths, Math.max(needed / 2, lobLengths.length * 2));
        }
        if (row.inOneBuffer()) {
            appendInOneCopy(row);
            rowCount++;
            return;
        }
        // A row that spanned two messages has its cells in two buffers, so
        // there is no single span to take. Rare, and it costs a copy per cell.
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
            lobLengths[index / 2] = row.lobLength(column);
            row.copyTo(column, data);
        }
        rowCount++;
    }


    /**
     * The whole row in <b>one</b> copy - the case where every cell is in the
     * message buffer.
     *
     * <p>The cells lie next to each other there, separated only by the lengths
     * and flags the protocol puts between them, so the span from the first to
     * the last moves at once and that filler rides along. A call into a checked
     * bulk copy costs about the same whatever it carries, so what this saves is
     * the number of calls: a hundred thousand rows of 160 bytes cost 1.29 ms
     * this way against 7.12 ms at twenty columns one cell at a time
     * ({@code space.seclume.bench.RowCopyProbe}).
     */
    private void appendInOneCopy(TtcRow row) {
        int from = -1;
        int to = -1;
        for (int column = 0; column < columnCount; column++) {
            if (row.isNull(column)) {
                continue;
            }
            int length = row.cellLength(column);
            if (length <= 0) {
                continue;
            }
            int at = row.cellAt(column);
            if (from < 0 || at < from) {
                from = at;
            }
            if (at + length > to) {
                to = at + length;
            }
        }
        int base = data.position();
        if (from >= 0) {
            data.putBytes(row.source(), from, to - from);
        }
        for (int column = 0; column < columnCount; column++) {
            int index = (rowCount * columnCount + column) * 2;
            int length = row.isNull(column) ? -1 : row.cellLength(column);
            if (length < 0) {
                cells[index] = 0;
                cells[index + 1] = -1;
                continue;
            }
            cells[index] = length == 0 ? base : base + (row.cellAt(column) - from);
            cells[index + 1] = length;
            lobLengths[index / 2] = row.lobLength(column);
        }
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

    List<OracleColumn> columns() {
        return columns;
    }

    OracleColumn column(int index) {
        return columns.get(index);
    }

    void select(int row) {
        this.current = row;
    }

    WireBuffer data() {
        return data;
    }

    int offset(int column) {
        return cells[(current * columnCount + column) * 2];
    }

    int length(int column) {
        return cells[(current * columnCount + column) * 2 + 1];
    }

    /**
     * How long the LOB in that column is.
     *
     * <p>Free: the length came with the row, next to the locator.
     */
    long lobLength(int column) {
        return lobLengths[(current * columnCount + column)];
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
