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
}
