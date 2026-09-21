package space.seclume.postgresql.jdbc;

import java.lang.foreign.MemorySegment;
import java.util.Arrays;
import java.util.List;

import space.seclume.postgresql.PgSession;
import space.seclume.postgresql.Row;
import space.seclume.internal.WireBuffer;

/**
 * The rows of a result, buffered - but off-heap.
 *
 * <p>JDBC requires a {@code ResultSet} to still be there after the query; the
 * window onto the receive buffer is not enough for that. The usual way out is
 * an {@code Object[]} per row with a {@code String} per cell - at 10,000 rows
 * of ten columns that is 110,000 objects the GC has to collect again
 * afterwards.
 *
 * <p>Here nothing is copied at all. The bytes are already in the receive
 * buffer; this class writes down the start and length of every cell in one
 * {@code int} array, and when the statement is done the result <b>takes the
 * buffer over</b> and hands the session its own in exchange. A Java object
 * only comes into being when somebody calls {@code getString} - and with
 * {@code getLong} none at all.
 *
 * <p>The block belongs to the statement and is <b>reused</b> for every
 * execution, not built anew. That is not a micro-optimisation: a fresh block
 * means a native allocation and a free per statement, and a benchmark against
 * pgjdbc showed exactly that as the difference - four and a half times the
 * garbage per query for a result of one row. JDBC allows it, because
 * re-executing a statement invalidates the previous {@code ResultSet} anyway.
 */
final class ResultBlock implements AutoCloseable {

    /** How many rows the cell index has room for before it grows. */
    private static final int INITIAL_ROWS = 64;

    private WireBuffer data;
    private List<PgSession.Field> fields;
    private int columns;
    /** Two entries per cell: start within the block and length (-1 = SQL NULL). */
    private int[] cells;
    private int rowCount;
    /** Bytes of row data held - what a result limit is measured against. */
    private long bytes;

    ResultBlock(List<PgSession.Field> fields) {
        this.data = new WireBuffer(8 * 1024);
        this.cells = new int[0];
        reset(fields);
    }

    /**
     * Takes the block over for the next result: same memory, new columns.
     *
     * <p>The bytes of the previous result are not wiped - they are payload,
     * not a secret, and they are overwritten as the new rows arrive. What must
     * be right is the position, and that is what {@code clear} sets.
     */
    void reset(List<PgSession.Field> fields) {
        this.fields = fields;
        this.columns = fields.size();
        this.rowCount = 0;
        this.bytes = 0;
        int needed = Math.max(columns, 1) * 2 * INITIAL_ROWS;
        if (cells.length < needed) {
            cells = new int[needed];
        }
    }

    /**
     * Takes a row over - by writing down where it is, not by copying it.
     *
     * <p>The bytes are already in the receive buffer, and at the end of the
     * statement the result takes that whole buffer over (see
     * {@link #adopt}). So there is nothing to copy here: two numbers per cell
     * and the row is kept.
     */
    void append(Row row) {
        int needed = (rowCount + 1) * columns * 2;
        if (needed > cells.length) {
            cells = Arrays.copyOf(cells, Math.max(needed, cells.length * 2));
        }
        int base = rowCount * columns * 2;
        for (int column = 0; column < columns; column++) {
            int index = base + column * 2;
            int length = row.length(column);
            cells[index] = length < 0 ? 0 : row.offset(column);
            cells[index + 1] = length;
            if (length > 0) {
                bytes += length;
            }
        }
        rowCount++;
    }

    /**
     * Takes the buffer with the rows over and gives back the empty one.
     *
     * <p>The two swap places: what the session read into becomes the memory of
     * this result, and the memory this result had becomes what the session
     * reads into next. Nothing is allocated and nothing is copied.
     */
    void adopt(java.util.function.UnaryOperator<WireBuffer> exchange) {
        this.data = exchange.apply(this.data);
    }

    int rowCount() {
        return rowCount;
    }

    /**
     * How many bytes of row data are in here.
     *
     * <p>Added up while the rows arrive, in a loop that runs anyway - the
     * alternative would be to walk the whole block afterwards, and by then the
     * memory it is meant to protect is already gone.
     */
    long bytes() {
        return bytes;
    }

    int columnCount() {
        return columns;
    }

    List<PgSession.Field> fields() {
        return fields;
    }

    boolean isNull(int row, int column) {
        return cells[(row * columns + column) * 2 + 1] < 0;
    }

    int offset(int row, int column) {
        return cells[(row * columns + column) * 2];
    }

    int length(int row, int column) {
        return cells[(row * columns + column) * 2 + 1];
    }

    WireBuffer data() {
        return data;
    }

    byte byteAt(int position) {
        return data.getByte(position);
    }

    /**
     * The decimal integer at {@code position} - see
     * {@link space.seclume.internal.jdbc.TextNumber}, which is where the eight
     * bytes per access are explained.
     */
    long decimalAt(int position, int length) {
        return space.seclume.internal.jdbc.TextNumber.decimal(data, position, length);
    }

    /**
     * Frees the native block. Called when the <b>statement</b> closes, not
     * when a {@code ResultSet} does: the next execution reuses this memory.
     */
    @Override
    public void close() {
        data.close();
        Arrays.fill(cells, 0);
        rowCount = 0;
    }
}
