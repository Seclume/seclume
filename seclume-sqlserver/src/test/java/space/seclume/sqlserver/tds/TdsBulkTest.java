package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Column types for bulk loads and table-valued parameters: never narrower
 * than a value that has to go in (found in review, 25.09.2026 - a double in a
 * column typed real from a float before it lost half its digits).
 */
class TdsBulkTest {

    @Test
    void aDoubleAfterAFloatMakesTheColumnFloat() throws SQLException {
        List<Object[]> sample = List.of(new Object[] {1.5f}, new Object[] {0.1234567890123d});
        List<TdsBulk.Column> columns = TdsBulk.columns(new String[] {"x"}, sample, null);
        assertEquals(TdsBulk.Kind.FLOAT, columns.get(0).kind());
        TdsBulk.check(columns, sample.get(1), 2);
    }

    @Test
    void aLongAfterAnIntMakesTheColumnBigint() throws SQLException {
        List<Object[]> sample = List.of(new Object[] {1}, new Object[] {1L << 40});
        assertEquals(TdsBulk.Kind.BIGINT,
                TdsBulk.columns(new String[] {"n"}, sample, null).get(0).kind());
    }

    @Test
    void aDoubleIsRefusedInARealColumnRatherThanCut() throws SQLException {
        List<TdsBulk.Column> columns = TdsBulk.columns(new String[] {"x"},
                List.<Object[]>of(new Object[] {1.5f}), null);
        assertEquals(TdsBulk.Kind.REAL, columns.get(0).kind());
        SQLException refused = assertThrows(SQLException.class,
                () -> TdsBulk.check(columns, new Object[] {0.1234567890123d}, 1001));
        assertEquals("22005", refused.getSQLState());
    }
}
