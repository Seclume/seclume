package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;

import space.seclume.internal.jdbc.JdbcEscapes.Dialect;

/**
 * The escapes, per server - and above all what must be left alone.
 *
 * <p>A translator that rewrites a brace inside a string literal breaks a
 * query that worked before it existed, which is the worse failure of the two.
 * So half of these are about text that has to come out exactly as it went in.
 */
class JdbcEscapesTest {

    private static String pg(String sql) {
        return JdbcEscapes.translate(sql, Dialect.POSTGRESQL);
    }

    private static String ora(String sql) {
        return JdbcEscapes.translate(sql, Dialect.ORACLE);
    }

    @Test
    void withoutABraceNothingHappensAtAll() {
        String sql = "select 1";
        assertSame(sql, pg(sql));
    }

    @Test
    void sqlServerGetsTheTextUnchangedItSpeaksOdbcEscapes() {
        String sql = "select {fn ucase('a')}, {ts '2026-09-23 10:15:30'}";
        assertSame(sql, JdbcEscapes.translate(sql, Dialect.SQLSERVER));
    }

    @Test
    void mySqlGetsOnlyTheEscapeClauseItCannotParse() {
        assertEquals("select {fn ucase(note)} from t where note like 'a!_b' ESCAPE '!'",
                JdbcEscapes.translate(
                        "select {fn ucase(note)} from t where note like 'a!_b' {escape '!'}",
                        Dialect.MYSQL));
    }

    @Test
    void dateTimeAndTimestampLiterals() {
        assertEquals("values (DATE '2026-09-23', TIME '10:15:30', TIMESTAMP '2026-09-23 10:15:30')",
                pg("values ({d '2026-09-23'}, {t '10:15:30'}, {ts '2026-09-23 10:15:30'})"));
        assertEquals("select TO_DATE('10:15:30', 'HH24:MI:SS') from dual",
                ora("select {t '10:15:30'} from dual"));
    }

    @Test
    void functionsAreMappedPerServer() {
        assertEquals("select UPPER(note), (note || '!'), STRPOS(note, 'b') from t",
                pg("select {fn ucase(note)}, {fn concat(note, '!')}, {fn locate('b', note)} from t"));
        assertEquals("select UPPER(note), CONCAT(note, '!'), INSTR(note, 'b') from t",
                ora("select {fn ucase(note)}, {fn concat(note, '!')}, {fn locate('b', note)} from t"));
        assertEquals("select COALESCE(a, 0), EXTRACT(YEAR FROM d), CURRENT_TIMESTAMP",
                pg("select {fn ifnull(a, 0)}, {fn year(d)}, {fn now()}"));
    }

    @Test
    void escapesNestAndArgumentsKeepTheirCommas() {
        assertEquals("select (UPPER(a) || LOWER(f(b, c)))",
                pg("select {fn concat({fn ucase(a)}, {fn lcase(f(b, c))})}"));
    }

    @Test
    void anUnknownFunctionKeepsItsName() {
        assertEquals("select soundex(name) from t", pg("select {fn soundex(name)} from t"));
    }

    @Test
    void anOuterJoinEscapeIsTheJoinAsWritten() {
        assertEquals("select * from a left outer join b on a.id = b.id",
                pg("select * from {oj a left outer join b on a.id = b.id}"));
    }

    /** The half that matters most: braces that are not escapes. */
    @Test
    void bracesThatAreNotEscapesAreLeftAlone() {
        String[] untouched = {
            "select '{1,2,3}'::int[]",                              // an array literal
            "select '{fn ucase(x)}'",                               // an escape inside a string
            "select \"{d\" from t",                                 // a quoted identifier
            "select 1 -- {fn ucase(x)}\n",                          // a line comment
            "select /* {ts '2026-01-01'} */ 1",                     // a block comment
            "select $$ {fn ucase(x)} $$",                           // a dollar quote
            "select $body$ {d '2026-01-01'} $body$",                // a tagged one
            "select 'it''s {fn x()}'",                              // a doubled quote
            "select jsonb_build_object('a', 1) @> '{\"a\": 1}'",    // JSON in a literal
            "select {unknown thing}",                               // not an escape keyword
        };
        for (String sql : untouched) {
            assertEquals(sql, pg(sql), "changed: " + sql);
        }
    }

    @Test
    void theBackslashEscapeOfMySqlDoesNotEndAString() {
        String sql = "select 'a\\'{escape x}' from t";
        assertEquals(sql, JdbcEscapes.translate(sql, Dialect.MYSQL));
    }

    @Test
    void likeWithAnEscapeCharacter() {
        assertEquals("select id from t where note like 'a!_b' ESCAPE '!'",
                ora("select id from t where note like 'a!_b' {escape '!'}"));
    }
}
