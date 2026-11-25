package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.MemorySegment;
import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * A value a hostile server cut short, or filled with a count past its end: an
 * SQLException with a data state, not an IndexOutOfBoundsException out of the
 * getter that {@code catch (SQLException e)} lets by - read in the fuzzer
 * 97,104 times for a ROWID and 14,502 times for a DATE in 100,000 values.
 */
class ShortValuesTest {

    private static MemorySegment cell(int... bytes) {
        byte[] raw = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            raw[i] = (byte) bytes[i];
        }
        return MemorySegment.ofArray(raw);
    }

    @Test
    void aRowidWhoseFieldRunsPastItsEndIsADataError() {
        // A count of 4, and one byte after it.
        SQLException refused = assertThrows(SQLException.class,
                () -> OracleRowid.toText(cell(4, 1), 0, 2));
        assertEquals("22000", refused.getSQLState());
        // And past the buffer itself.
        assertThrows(SQLException.class, () -> OracleRowid.toText(cell(0x7f), 0, 1));
    }

    @Test
    void aWholeRowidStillReads() throws SQLException {
        MemorySegment rowid = cell(4, 0, 0, 0x12, 0x34, 2, 0, 5, 0, 4, 0, 0, 1, 0, 2, 0, 3);
        assertEquals(18, OracleRowid.toText(rowid, 0, (int) rowid.byteSize()).length());
    }

    @Test
    void aDateShorterThanSevenBytesIsADataError() {
        SQLException refused = assertThrows(SQLException.class,
                () -> OracleDate.fields(cell(120, 126, 1), 0, 3));
        assertEquals("22000", refused.getSQLState());
    }

    @Test
    void aDateThatCannotExistIsADataError() {
        // Month 13.
        SQLException refused = assertThrows(SQLException.class,
                () -> OracleDate.fields(cell(120, 126, 13, 1, 1, 1, 1), 0, 7));
        assertEquals("22007", refused.getSQLState());
    }
}
