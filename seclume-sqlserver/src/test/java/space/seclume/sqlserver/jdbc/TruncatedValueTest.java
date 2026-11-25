package space.seclume.sqlserver.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;
import space.seclume.sqlserver.tds.TdsTypes;
import space.seclume.sqlserver.tds.TdsValues;

/**
 * A value whose bytes end before its length says reaches the caller as an
 * SQLException: WireBuffer.Truncated is an IllegalStateException, and left
 * asText, asLong, asDouble, asBoolean and asBigDecimal - and so the getters -
 * past {@code catch (SQLException e)}. Every value getter of TdsResultSet
 * decodes through {@code decoded}.
 */
class TruncatedValueTest {

    private static WireBuffer buffer(int... bytes) {
        WireBuffer in = new WireBuffer(bytes.length + 16);
        for (int b : bytes) {
            in.putByte((byte) b);
        }
        in.position(0);
        in.limit(bytes.length);
        return in;
    }

    @Test
    void aValueCutShortIsAnSqlException() {
        try (WireBuffer in = buffer('a', 'b', 'c')) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> TdsResultSet.decoded(2, () -> TdsValues.asText(in, TdsTypes.BIGVARCHAR,
                            0, Integer.MAX_VALUE - 8, 0)));
            assertEquals("08S01", refused.getSQLState());
            assertTrue(refused.getMessage().contains("column 3"), refused.getMessage());
            assertTrue(refused.getCause() instanceof WireBuffer.Truncated);
            assertThrows(SQLException.class,
                    () -> TdsResultSet.decoded(0, () -> TdsValues.asBytes(in, 0, -1)));
        }
    }

    @Test
    void aWholeValueComesThrough() throws SQLException {
        try (WireBuffer in = buffer('a', 'b', 'c')) {
            assertEquals("abc", TdsResultSet.decoded(0,
                    () -> TdsValues.asText(in, TdsTypes.BIGVARCHAR, 0, 3, 0)));
        }
    }
}
