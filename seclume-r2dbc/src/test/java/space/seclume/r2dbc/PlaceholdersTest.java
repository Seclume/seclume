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

    @Test
    void numbersBeyondAnIntAreStillOrderedByValue() {
        Placeholders.Parsed parsed = Placeholders.parse(
                "select $99999999999, $10, $9, $010", Dialect.POSTGRESQL);
        // $010 is $10, as PostgreSQL reads it: one parameter, written twice
        assertEquals(List.of("$9", "$10", "$99999999999"),
                List.copyOf(parsed.positions().keySet()));
        assertArrayEquals(new int[] {2, 4}, parsed.positions().get("$10"));
    }

    /**
     * Found in the third review round, 11.11.2026: an index was the n-th
     * placeholder written, so in "$1 ... $3" index 1 bound $3 - and "$01"
     * and "$1", one parameter to PostgreSQL, took two values. An index is
     * now $(index+1), as PostgreSQL and its own R2DBC driver count, and one
     * the statement does not have is refused.
     */
    @Test
    void aPostgresIndexIsItsNumberEvenWithAGap() {
        Placeholders.Parsed parsed = Placeholders.parse("update t set a = $1 where id = $3",
                Dialect.POSTGRESQL);
        assertEquals("$1", parsed.nameOf(0));
        assertThrows(IndexOutOfBoundsException.class, () -> parsed.nameOf(1));
        assertEquals("$3", parsed.nameOf(2));
        assertThrows(IndexOutOfBoundsException.class, () -> parsed.nameOf(-1));
        assertThrows(IndexOutOfBoundsException.class, () -> parsed.nameOf(Integer.MAX_VALUE));

        Placeholders.Parsed padded = Placeholders.parse("select $01, $1, $002", Dialect.POSTGRESQL);
        assertEquals(List.of("$1", "$2"), List.copyOf(padded.positions().keySet()));
        assertArrayEquals(new int[] {1, 2}, padded.positions().get("$1"));
        assertEquals("$2", padded.nameOf(1));
    }

    @Test
    void postgresEscapeStringsEndWhereTheirQuoteIsNotEscaped() {
        String sql = "select E'it\\'s $1', e'\\\\', $1, 'plain\\' , $2";
        Placeholders.Parsed parsed = Placeholders.parse(sql, Dialect.POSTGRESQL);
        assertEquals("select E'it\\'s $1', e'\\\\', ?, 'plain\\' , ?", parsed.sql());
        assertEquals(List.of("$1", "$2"), List.copyOf(parsed.positions().keySet()));
        // An identifier ending in e before a quote is not an E string: the
        // backslash is a character and the quote ends the literal.
        Placeholders.Parsed name = Placeholders.parse("select type'\\', $1",
                Dialect.POSTGRESQL);
        assertEquals("select type'\\', ?", name.sql());
        assertEquals(1, name.count());
    }

    @Test
    void aDollarInsideAPostgresIdentifierIsPartOfIt() {
        Placeholders.Parsed parsed = Placeholders.parse(
                "select col$1, t$x$.a, \"q$2\" from t$1 where c = $1 and d = ($2)",
                Dialect.POSTGRESQL);
        assertEquals("select col$1, t$x$.a, \"q$2\" from t$1 where c = ? and d = (?)",
                parsed.sql());
        assertEquals(List.of("$1", "$2"), List.copyOf(parsed.positions().keySet()));
        assertArrayEquals(new int[] {1}, parsed.positions().get("$1"));
    }

    @Test
    void postgresDollarQuotesStillOpenAfterAnOperator() {
        Placeholders.Parsed parsed = Placeholders.parse(
                "select $1||$a$ $2 $a$, ($$ $3 $$), $2", Dialect.POSTGRESQL);
        assertEquals("select ?||$a$ $2 $a$, ($$ $3 $$), ?", parsed.sql());
        assertEquals(List.of("$1", "$2"), List.copyOf(parsed.positions().keySet()));
    }

    @Test
    void oracleAlternativeQuotingIsALiteral() {
        String sql = "select q'[it's :a]', Q'{:b}', q'(:c)', q'<:d>', q'!:e's!', nq'#:f#',"
                + " :g from t where x = :h";
        Placeholders.Parsed parsed = Placeholders.parse(sql, Dialect.ORACLE);
        assertEquals("select q'[it's :a]', Q'{:b}', q'(:c)', q'<:d>', q'!:e's!', nq'#:f#',"
                + " ? from t where x = ?", parsed.sql());
        assertEquals(List.of("g", "h"), List.copyOf(parsed.positions().keySet()));
    }

    @Test
    void anOracleNameEndingInQIsNotAQuote() {
        Placeholders.Parsed parsed = Placeholders.parse(
                "select seq'x', :a, 'y' from dual where b = :b", Dialect.ORACLE);
        // seq'x' is the column seq and the literal 'x'; the parameters are code.
        assertEquals("select seq'x', ?, 'y' from dual where b = ?", parsed.sql());
        assertEquals(2, parsed.count());
    }

    @Test
    void anUnclosedOracleQuoteRunsToTheEnd() {
        Placeholders.Parsed parsed = Placeholders.parse("select q'[ :a ' :b", Dialect.ORACLE);
        assertEquals("select q'[ :a ' :b", parsed.sql());
        assertEquals(0, parsed.count());
        Placeholders.Parsed spaced = Placeholders.parse("select q' :a' , :b", Dialect.ORACLE);
        // a blank is no delimiter: q is a name and ' :a' a literal
        assertEquals("select q' :a' , ?", spaced.sql());
    }
}
