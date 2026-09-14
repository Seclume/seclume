package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * The rewrite from {@code ?} to {@code $n} - position by position.
 *
 * <p>These tests are the real safeguard against the obvious mistake: replacing
 * a question mark that is not one.
 */
class PgSqlRewriterTest {

    private static String rewrite(String sql) throws SQLException {
        return PgSqlRewriter.rewrite(sql).sql();
    }

    @Test
    void numbersThePlaceholders() throws Exception {
        assertEquals("select $1, $2 where id = $3",
                rewrite("select ?, ? where id = ?"));
        assertEquals(3, PgSqlRewriter.rewrite("select ?, ? where id = ?").parameters());
    }

    @Test
    void leavesQuestionMarksInsideLiteralsAlone() throws Exception {
        assertEquals("select 'wirklich?' , $1", rewrite("select 'wirklich?' , ?"));
        assertEquals("select \"spalte?\" from t where a = $1",
                rewrite("select \"spalte?\" from t where a = ?"));
        // A doubled quote does not end the literal.
        assertEquals("select 'a''b?c', $1", rewrite("select 'a''b?c', ?"));
    }

    @Test
    void leavesQuestionMarksInCommentsAlone() throws Exception {
        assertEquals("select 1 -- was? \nwhere a = $1",
                rewrite("select 1 -- was? \nwhere a = ?"));
        assertEquals("select /* ? und /* geschachtelt ? */ noch */ $1",
                rewrite("select /* ? und /* geschachtelt ? */ noch */ ?"));
    }

    @Test
    void leavesDollarQuotedBodiesAlone() throws Exception {
        assertEquals("do $$ begin raise notice 'was?'; end $$; select $1",
                rewrite("do $$ begin raise notice 'was?'; end $$; select ?"));
        assertEquals("select $tag$ ? $tag$, $1", rewrite("select $tag$ ? $tag$, ?"));
    }

    @Test
    void keepsTheJsonbOperators() throws Exception {
        assertEquals("select data ?| array['a'] and data ?& array['b'] from t",
                rewrite("select data ?| array['a'] and data ?& array['b'] from t"));
        // ?? is the escaped single question mark.
        assertEquals("select data ? array['a']", rewrite("select data ?? array['a']"));
    }

    @Test
    void castsAreNotPlaceholders() throws Exception {
        assertEquals("select $1::text, x::int", rewrite("select ?::text, x::int"));
    }

    @Test
    void unterminatedLiteralsAreRejected() {
        assertThrows(SQLException.class, () -> rewrite("select 'offen"));
        assertThrows(SQLException.class, () -> rewrite("select /* offen"));
    }
}
