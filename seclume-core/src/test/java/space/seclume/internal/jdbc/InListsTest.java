package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigDecimal;
import java.sql.SQLException;
import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.internal.jdbc.InLists.Bound;
import space.seclume.internal.jdbc.InLists.Dialect;
import space.seclume.internal.jdbc.InLists.Kind;

/** The text side of lists bound to {@code in (?)}; the servers' side is InListTest. */
class InListsTest {

    @Test
    void onlyTheListPlaceholderChanges() throws SQLException {
        Bound[] lists = InLists.note(null, 2, InLists.of(List.of(1, 2), Dialect.POSTGRESQL));
        assertEquals("select * from t where a = ? and b = any(cast(? as bigint[])) and c = ?",
                InLists.apply("select * from t where a = ? and b in (?) and c = ?", lists,
                        Dialect.POSTGRESQL));
    }

    @Test
    void notInAndSpacingAndCase() throws SQLException {
        Bound[] lists = InLists.note(null, 1, InLists.of(List.of("x"), Dialect.POSTGRESQL));
        assertEquals("select 1 where b <> all(cast(? as text[]))",
                InLists.apply("select 1 where b NOT  IN (  ? )", lists, Dialect.POSTGRESQL));
        assertEquals("select 1 where b NOT  IN (select v from openjson(?) with (v nvarchar(max) '$'))",
                InLists.apply("select 1 where b NOT  IN (  ? )",
                        InLists.note(null, 1, InLists.of(List.of("x"), Dialect.SQLSERVER)),
                        Dialect.SQLSERVER));
    }

    @Test
    void questionMarksInCommentsAndStringsAreNotPlaceholders() throws SQLException {
        Bound[] lists = InLists.note(null, 1, InLists.of(List.of(1), Dialect.ORACLE));
        assertEquals("select '?' /* in (?) */ from t where id in (select v from json_table(?, "
                        + "'$[*]' columns (v number path '$')))",
                InLists.apply("select '?' /* in (?) */ from t where id in (?)", lists,
                        Dialect.ORACLE));
    }

    @Test
    void aListOutsideInIsRefused() throws SQLException {
        for (String sql : List.of("select min(?)", "select 1 where x = (?)", "select join(?)",
                "select 1 where x in (?, 2)")) {
            Bound[] lists = InLists.note(null, 1, InLists.of(List.of(1), Dialect.MYSQL));
            SQLException refused = assertThrows(SQLException.class,
                    () -> InLists.apply(sql, lists, Dialect.MYSQL), sql);
            assertEquals("22023", refused.getSQLState());
        }
    }

    /** Found by the fuzzer: an "in" at the end of a comment is not the operator. */
    @Test
    void anInInsideACommentIsNotTheOperator() throws SQLException {
        Bound[] lists = InLists.note(null, 1, InLists.of(List.of(1), Dialect.POSTGRESQL));
        assertThrows(SQLException.class,
                () -> InLists.apply("select 1 --in\n(?)", lists, Dialect.POSTGRESQL));
        assertEquals("select 1 where x = any(cast(? as bigint[]))",
                InLists.apply("select 1 where x in /* the ids */ (?)", lists, Dialect.POSTGRESQL));
    }

    @Test
    void theElementsDecideTheType() throws SQLException {
        Bound decimals = InLists.of(List.of(1, new BigDecimal("123.456"), 2.5), Dialect.SQLSERVER);
        assertEquals(Kind.DECIMAL, decimals.kind());
        assertEquals(6, decimals.precision());
        assertEquals(3, decimals.scale());
        assertEquals("[1,123.456,2.5]", decimals.payload());
        assertEquals("{\"a\\\"b\",\"c\\\\d\",\"NULL\"}",
                InLists.of(List.of("a\"b", "c\\d", "NULL"), Dialect.POSTGRESQL).payload());
        assertEquals("[\"a\\\"b\",\"line\\nbreak\"]",
                InLists.of(new String[] {"a\"b", "line\nbreak"}, Dialect.MYSQL).payload());
        assertThrows(SQLException.class, () -> InLists.of(List.of(1, "a"), Dialect.MYSQL));
        assertThrows(SQLException.class,
                () -> InLists.of(List.of(new Object()), Dialect.MYSQL));
    }

    @Test
    void anOrdinaryValueLeavesTheTextAlone() throws SQLException {
        assertNull(InLists.of(42, Dialect.MYSQL));
        assertNull(InLists.of(new byte[] {1}, Dialect.MYSQL));
        String sql = "select 1 where x in (?)";
        assertSame(sql, InLists.apply(sql, null, Dialect.MYSQL));
        assertSame(sql, InLists.apply(sql, InLists.note(null, 1, null), Dialect.MYSQL));
    }
}
