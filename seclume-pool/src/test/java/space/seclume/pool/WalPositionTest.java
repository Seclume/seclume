package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;

class WalPositionTest {
    @Test
    void bothHalvesKeepTheirUnsignedBits() throws SQLException {
        assertEquals(0x12345678abcdef01L, ReadWriteSplit.parseLsn("12345678/ABCDEF01"));
        assertEquals(-1L, ReadWriteSplit.parseLsn("FFFFFFFF/ffffffff"));
        assertEquals(0L, ReadWriteSplit.parseLsn(null));
        assertEquals(0L, ReadWriteSplit.parseLsn("0/0"));
    }

    @Test
    void malformedPositionsAreSqlErrors() {
        for (String value : new String[] {"", "1234", "/1", "1/", "1/2/3", "-1/0",
                "+1/0", "g/0", "100000000/0", "0/100000000", "1/ 2"}) {
            SQLException error = assertThrows(SQLException.class,
                    () -> ReadWriteSplit.parseLsn(value), value);
            assertEquals("22018", error.getSQLState());
        }
    }

    /**
     * Every hex digit at the edge of its range is read, and the character just
     * outside each range is refused - PIT left the range checks with a
     * comparison one off undetected (run 43416680859).
     */
    @Test
    void eachEdgeOfTheHexDigitRangesIsReadAndItsNeighbourRefused() throws SQLException {
        assertEquals(0x9L << 32 | 0x90L, ReadWriteSplit.parseLsn("9/90"));
        assertEquals(0xAL << 32 | 0xaL, ReadWriteSplit.parseLsn("A/a"));
        assertEquals(0xFL << 32 | 0xfL, ReadWriteSplit.parseLsn("F/f"));
        assertEquals(0x0A9L << 32 | 0x0a9L, ReadWriteSplit.parseLsn("0A9/0a9"));
        for (String value : new String[] {":/0", "0/:", "`/0", "0/`", "@/0", "0/@", "G/0", "0/g"}) {
            SQLException error = assertThrows(SQLException.class,
                    () -> ReadWriteSplit.parseLsn(value), value);
            assertEquals("22018", error.getSQLState(), value);
        }
    }

    /** Of two GTID sets with as many transactions, the one already known stays. */
    @Test
    void ofTwoEqualGtidSetsTheFirstStays() {
        String known = "3e11fa47-71ca-11e1-9e33-c80aa9429562:1-5";
        String other = "4f22ab58-82db-22f2-af44-d91bb0530673:1-5";
        assertEquals(known, ReadWriteSplit.later(known, other));
        assertEquals(other, ReadWriteSplit.later(other, known));
    }
}
