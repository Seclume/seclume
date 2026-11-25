package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLDataException;
import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * A value a driver cannot parse - "abc" asked for as a double, a bytea with a
 * character that is no hex digit - escaped as a NumberFormatException or an
 * IllegalArgumentException, through code that catches SQLException: a pool
 * took the connection for broken, and an application got "already closed"
 * from the next call. Every getter turns it into an SQLDataException with
 * the parse failure as its cause.
 */
class ReadOnlyResultSetTest {

    /** One row, one column, and a driver that fails the way the real ones do. */
    private static ReadOnlyResultSet failing(RuntimeException onBytes, RuntimeException onDouble)
            throws SQLException {
        ReadOnlyResultSet rows = new ReadOnlyResultSet(null) {
            @Override
            protected int rowCount() {
                return 1;
            }

            @Override
            protected int columnCount() {
                return 1;
            }

            @Override
            protected void moveTo(int row) {
            }

            @Override
            protected boolean isNullAt(int column) {
                return false;
            }

            @Override
            protected String stringAt(int column) {
                return "abc";
            }

            @Override
            protected long longAt(int column) {
                throw new NumberFormatException("abc");
            }

            @Override
            protected double doubleAt(int column) {
                throw onDouble;
            }

            @Override
            protected byte[] bytesAt(int column) {
                throw onBytes;
            }

            @Override
            protected boolean booleanAt(int column) {
                return false;
            }

            @Override
            protected Object objectAt(int column) {
                return "abc";
            }

            @Override
            protected int columnIndexOf(String label) {
                return 0;
            }

            @Override
            protected java.sql.ResultSetMetaData metaData() {
                return null;
            }

            @Override
            protected void release() {
            }
        };
        assertTrue(rows.next());
        return rows;
    }

    @Test
    void getBytesTurnsParseErrorsIntoSqlExceptions() throws SQLException {
        IllegalArgumentException badHex =
                new IllegalArgumentException("not a hex digit in a bytea value");
        try (ReadOnlyResultSet rows = failing(badHex, new NumberFormatException("abc"))) {
            SQLException refused = assertThrows(SQLException.class, () -> rows.getBytes(1));
            assertInstanceOf(SQLDataException.class, refused);
            assertSame(badHex, refused.getCause(), "the parse failure is the cause");
        }
    }

    @Test
    void anUnreadableValueIsAnSqlException() throws SQLException {
        NumberFormatException notANumber = new NumberFormatException("abc");
        try (ReadOnlyResultSet rows = failing(new IllegalArgumentException(), notANumber)) {
            SQLException refused = assertThrows(SQLException.class, () -> rows.getDouble(1));
            assertInstanceOf(SQLDataException.class, refused);
            assertSame(notANumber, refused.getCause());
            assertTrue(!rows.isClosed(), "a value it cannot read does not close the result");
        }
    }
}
