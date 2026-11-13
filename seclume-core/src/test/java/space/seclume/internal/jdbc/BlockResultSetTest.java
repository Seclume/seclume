package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * A result read in blocks - a fetch size - is one result to the application:
 * its row numbers go on across the blocks, only its first row is the first and
 * only its last the last. Each driver reads the next block through
 * {@code fetchMore}; these rows do it from a list.
 */
class BlockResultSetTest {

    /**
     * Rows 1 to {@code total} in blocks of {@code size}; {@code exact} says
     * whether the server tells the end with the last block or only by an
     * empty one after it, as a suspended portal does.
     */
    private static final class BlockRows extends ReadOnlyResultSet {
        private final int total;
        private final int size;
        private final boolean exact;
        private int first;
        private int count;
        private int current;
        int fetches;

        BlockRows(int total, int size, boolean exact) {
            super(null);
            this.total = total;
            this.size = size;
            this.exact = exact;
            this.count = Math.min(size, total);
        }

        @Override protected boolean fetchMore() {
            if (!mayFetchMore()) {
                return false;
            }
            fetches++;
            first += count;
            count = Math.min(size, total - first);
            return true;
        }
        @Override protected boolean mayFetchMore() {
            boolean full = count == size;
            return exact ? first + count < total : full;
        }
        @Override protected int rowCount() { return count; }
        @Override protected int columnCount() { return 1; }
        @Override protected void moveTo(int row) { current = first + row + 1; }
        @Override protected boolean isNullAt(int column) { return false; }
        @Override protected String stringAt(int column) { return Integer.toString(current); }
        @Override protected long longAt(int column) { return current; }
        @Override protected double doubleAt(int column) { return current; }
        @Override protected byte[] bytesAt(int column) { throw new UnsupportedOperationException(); }
        @Override protected boolean booleanAt(int column) { return current != 0; }
        @Override protected Object objectAt(int column) { return current; }
        @Override protected int columnIndexOf(String label) { return "n".equals(label) ? 0 : -1; }
        @Override protected ResultSetMetaData metaData() { throw new UnsupportedOperationException(); }
        @Override protected void release() { }
    }

    private static List<String> walk(BlockRows rows) throws SQLException {
        List<String> seen = new ArrayList<>();
        while (rows.next()) {
            String last;
            try {
                last = rows.isLast() ? " last" : "";
            } catch (SQLFeatureNotSupportedException unknown) {
                last = " last?";
            }
            seen.add(rows.getInt(1) + ":" + rows.getRow() + (rows.isFirst() ? " first" : "") + last);
        }
        return seen;
    }

    @Test
    void rowNumbersGoOnAcrossTheBlocks() throws Exception {
        BlockRows rows = new BlockRows(7, 3, true);
        assertTrue(rows.isBeforeFirst());
        assertEquals(0, rows.getRow());
        // "May" is all a driver says: more rows may follow a full block, and
        // its last row is not called the last - nor, without reading on, not.
        assertEquals(List.of("1:1 first", "2:2", "3:3 last?", "4:4", "5:5", "6:6 last?", "7:7 last"),
                walk(rows));
        assertEquals(2, rows.fetches);
        assertTrue(rows.isAfterLast());
        assertFalse(rows.isBeforeFirst());
        assertEquals(0, rows.getRow());
        assertFalse(rows.next());
        assertTrue(rows.isAfterLast());
    }

    /**
     * Where the server says the end only with an empty block after it, the
     * last row of a full block may or may not be the last: it is not said, it
     * is refused - a wrong {@code true} ended loops a block early.
     */
    @Test
    void theLastRowOfAFullBlockIsNotCalledTheLastWhenMoreMayCome() throws Exception {
        BlockRows rows = new BlockRows(7, 3, false);
        assertEquals(List.of("1:1 first", "2:2", "3:3 last?", "4:4", "5:5", "6:6 last?", "7:7 last"),
                walk(rows));
        BlockRows even = new BlockRows(6, 3, false);
        assertEquals(List.of("1:1 first", "2:2", "3:3 last?", "4:4", "5:5", "6:6 last?"), walk(even));
        assertTrue(even.isAfterLast(), "after the empty block that ended it");
        assertFalse(even.isBeforeFirst());
        assertFalse(even.isFirst());
        assertEquals(0, even.getRow());
        SQLException noRow = assertThrows(SQLException.class, () -> even.getInt(1));
        assertTrue(noRow.getMessage() != null);
        assertFalse(even.next());
        assertTrue(even.isAfterLast());
    }

    @Test
    void aResultInOneBlockIsAsBefore() throws Exception {
        BlockRows rows = new BlockRows(2, 10, false);
        assertEquals(List.of("1:1 first", "2:2 last"), walk(rows));
        assertTrue(rows.isAfterLast());
        BlockRows none = new BlockRows(0, 10, false);
        assertFalse(none.isBeforeFirst());
        assertFalse(none.next());
        assertFalse(none.isAfterLast(), "an empty result has no position after a last row");
        assertFalse(none.isFirst());
        assertFalse(none.isLast());
    }
}
