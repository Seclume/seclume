package space.seclume.r2dbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.r2dbc.Placeholders.Dialect;

/** Each database's placeholders as JDBC's, and nothing rewritten that is not code. */
class PlaceholdersTest {

    @Test
    void postgresNumbersAreBoundByNumberNotByOrder() {
        Placeholders.Parsed parsed = Placeholders.parse(
                "select * from t where b = $2 and a = $1 or a2 = $1", Dialect.POSTGRESQL);
        assertEquals("select * from t where b = ? and a = ? or a2 = ?", parsed.sql());
        assertEquals(List.of("$1", "$2"), List.copyOf(parsed.positions().keySet()));
        assertArrayEquals(new int[] {2, 3}, parsed.positions().get("$1"));
        assertArrayEquals(new int[] {1}, parsed.positions().get("$2"));
        assertEquals("$1", parsed.nameOf(0));
        assertEquals("$2", parsed.nameOf(1));
    }

    @Test
    void postgresLiteralsCommentsAndDollarBodiesAreLeftAlone() {
        String sql = "select '$1', \"$2\", $1 -- $3\n/* $4 */ "
                + "from f($$ select $5 $$, $body$ $6 $body$) where x::int = $2";
        Placeholders.Parsed parsed = Placeholders.parse(sql, Dialect.POSTGRESQL);
        assertEquals("select '$1', \"$2\", ? -- $3\n/* $4 */ "
                + "from f($$ select $5 $$, $body$ $6 $body$) where x::int = ?", parsed.sql());
        assertEquals(List.of("$1", "$2"), List.copyOf(parsed.positions().keySet()));
    }

    @Test
    void mysqlQuestionMarksArePositional() {
        Placeholders.Parsed parsed = Placeholders.parse(
                "insert into t (a, `b?`, c) values (?, '?', ?) # ?", Dialect.MYSQL);
        assertEquals("insert into t (a, `b?`, c) values (?, '?', ?) # ?", parsed.sql());
        assertEquals(2, parsed.count());
        assertArrayEquals(new int[] {1}, parsed.positions().get(parsed.nameOf(0)));
        assertArrayEquals(new int[] {2}, parsed.positions().get(parsed.nameOf(1)));
    }

    @Test
    void sqlServerNamesAndNotItsSystemFunctions() {
        Placeholders.Parsed parsed = Placeholders.parse(
                "select @@spid, [@x] from t where a = @Id and b = @name and c = @id",
                Dialect.SQLSERVER);
        assertEquals("select @@spid, [@x] from t where a = ? and b = ? and c = ?", parsed.sql());
        assertArrayEquals(new int[] {1, 3}, parsed.positions().get("id"));
        assertArrayEquals(new int[] {2}, parsed.positions().get("name"));
    }

    @Test
    void oracleNamesAndNotItsAssignments() {
        Placeholders.Parsed parsed = Placeholders.parse(
                "begin x := :a; update t set c = :B where d = ':c' and e = :a; end;",
                Dialect.ORACLE);
        assertEquals("begin x := ?; update t set c = ? where d = ':c' and e = ?; end;",
                parsed.sql());
        assertArrayEquals(new int[] {1, 3}, parsed.positions().get("a"));
        assertArrayEquals(new int[] {2}, parsed.positions().get("b"));
    }

    @Test
    void aBindIndexBeyondTheParametersIsRefused() {
        Placeholders.Parsed parsed = Placeholders.parse("select $1", Dialect.POSTGRESQL);
        assertThrows(IndexOutOfBoundsException.class, () -> parsed.nameOf(1));
    }
}
