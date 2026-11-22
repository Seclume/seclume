package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * In an escape string a backslash escapes: {@code E'it\'s ?'} is one literal
 * whose {@code ?} is text. Read as a plain literal it ended at the escaped
 * quote, the {@code ?} in it became {@code $1}, and a real one after it stayed
 * {@code ?} - an unterminated literal, or a statement the server refused.
 */
class PgSqlRewriterEscapeStringTest {

    private static String rewritten(String sql) throws Exception {
        return PgSqlRewriter.rewrite(sql).toString();
    }

    @Test
    void aQuestionMarkInAnEscapeStringIsText() throws Exception {
        assertEquals("Rewritten[sql=SELECT E'it\\'s ?' AS t, $1, parameters=1]",
                rewritten("SELECT E'it\\'s ?' AS t, ?"));
        assertEquals("Rewritten[sql=SELECT e'a\\'?' || $1::text || E'b\\\\' AS t WHERE $2 = 1, parameters=2]",
                rewritten("SELECT e'a\\'?' || ?::text || E'b\\\\' AS t WHERE ? = 1"));
    }

    @Test
    void anEOnlyStartsOneWhereItIsNotPartOfAWord() throws Exception {
        // NAME'...' is no escape string; a plain literal follows a word ending in e.
        assertEquals("Rewritten[sql=SELECT 'a\\' AS some, $1, parameters=1]",
                rewritten("SELECT 'a\\' AS some, ?"));
        assertEquals("Rewritten[sql=SELECT 1 FROM t WHERE name='x\\' AND id = $1, parameters=1]",
                rewritten("SELECT 1 FROM t WHERE name='x\\' AND id = ?"));
    }
}
