package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * {@code getInt} on a column holding {@code 'abc'}, on all four drivers: an
 * {@code SQLException} with SQLState 22018, as JDBC promises - not the
 * {@code NumberFormatException} the number parsers raise underneath, which a
 * caller catching {@code SQLException} would let through.
 */
@Timeout(120)
class TextIsNotANumberTest {

    @ParameterizedTest(name = "{0}")
    @MethodSource("space.seclume.pool.SessionResetTest#databases")
    void textIsReportedAsAnInvalidCast(SessionResetTest.Db db) throws Exception {
        String sql = db.name().equals("Oracle") ? "select 'abc' from dual" : "select 'abc'";
        try (Connection connection = DriverManager.getConnection(SessionResetTest.url(db));
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            assertTrue(rows.next());
            for (ThrowingRead read : new ThrowingRead[] {
                    () -> rows.getInt(1), () -> rows.getLong(1), () -> rows.getDouble(1),
                    () -> rows.getBigDecimal(1)}) {
                SQLException refused = assertThrows(SQLException.class, read::run);
                assertEquals("22018", refused.getSQLState(), refused.toString());
            }
            assertEquals("abc", rows.getString(1), "the row is still readable");
        }
    }

    @FunctionalInterface
    private interface ThrowingRead {
        Object run() throws SQLException;
    }
}
