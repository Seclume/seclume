package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.SQLDataException;
import java.sql.Types;
import java.util.List;

import org.junit.jupiter.api.Test;

class NumericResultSetTest {
    @Test
    void failedStringAndObjectConversionsLeaveTheCursorUsable() throws Exception {
        try (NumericRows rows = new NumericRows()) {
            assertTrue(rows.next());
            assertEquals("22018", assertThrows(SQLDataException.class,
                    () -> rows.getString("number")).getSQLState());
            assertEquals("22018", assertThrows(SQLDataException.class,
                    () -> rows.getObject(1)).getSQLState());
            assertFalse(rows.wasNull());
            assertEquals("bad-number", rows.getString("source"));
            assertTrue(rows.next());
            assertEquals("1.5", rows.getString(1));
            assertEquals(1.5, rows.getObject(1));
            assertTrue(rows.next());
            assertNull(rows.getString(1));
            assertNull(rows.getObject(1));
            assertTrue(rows.wasNull());
        }
    }

    private static final class NumericRows extends ReadOnlyResultSet {
        private final String[] values = {"bad-number", "1.5", null};
        private String current;

        NumericRows() {
            super(null);
        }

        @Override protected int rowCount() { return values.length; }
        @Override protected int columnCount() { return 2; }
        @Override protected void moveTo(int row) { current = values[row]; }
        @Override protected boolean isNullAt(int column) { return current == null; }
        @Override protected String stringAt(int column) throws NumberFormatException {
            return column == 1 ? current : Double.toString(Double.parseDouble(current));
        }
        @Override protected long longAt(int column) throws NumberFormatException { return Long.parseLong(current); }
        @Override protected double doubleAt(int column) throws NumberFormatException { return Double.parseDouble(current); }
        @Override protected byte[] bytesAt(int column) { throw new UnsupportedOperationException(); }
        @Override protected boolean booleanAt(int column) { return Boolean.parseBoolean(current); }
        @Override protected Object objectAt(int column) throws NumberFormatException {
            return column == 1 ? current : Double.valueOf(current);
        }
        @Override protected int columnIndexOf(String label) {
            return switch (label) { case "number" -> 0; case "source" -> 1; default -> -1; };
        }
        @Override protected ResultSetMetaData metaData() throws SQLException {
            return new ListResultSet(new String[] {"number", "source"},
                    new int[] {Types.DOUBLE, Types.VARCHAR}, new String[] {"double", "text"},
                    List.of()).getMetaData();
        }
        @Override protected void release() { }
    }
}
