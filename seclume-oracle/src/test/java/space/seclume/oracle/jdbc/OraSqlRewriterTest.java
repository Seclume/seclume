package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * Question marks into Oracle's numbered binds - and everywhere a question mark
 * is not one.
 *
 * <p>Every case here is one that a {@code String.replace} gets wrong, which is
 * the whole reason the rewriter reads the text instead.
 */
class OraSqlRewriterTest {

    @Test
    void numbersThePlaceholdersFromOne() throws SQLException {
        OraSqlRewriter.Rewritten rewritten =
                OraSqlRewriter.rewrite("select * from t where a = ? and b = ?");
        assertEquals("select * from t where a = :1 and b = :2", rewritten.sql());
        assertEquals(2, rewritten.parameters());
    }

    @Test
    void leavesAQuestionMarkInsideAStringAlone() throws SQLException {
        OraSqlRewriter.Rewritten rewritten =
                OraSqlRewriter.rewrite("select 'really?' from dual where a = ?");
        assertEquals("select 'really?' from dual where a = :1", rewritten.sql());
        assertEquals(1, rewritten.parameters());
    }

    @Test
    void understandsTheDoubledQuote() throws SQLException {
        OraSqlRewriter.Rewritten rewritten =
                OraSqlRewriter.rewrite("select 'it''s a test? yes' from dual where a = ?");
        assertEquals("select 'it''s a test? yes' from dual where a = :1", rewritten.sql());
        assertEquals(1, rewritten.parameters());
    }

    @Test
    void leavesAQuestionMarkInsideAnIdentifierAlone() throws SQLException {
        OraSqlRewriter.Rewritten rewritten =
                OraSqlRewriter.rewrite("select \"what?\" from t where a = ?");
        assertEquals("select \"what?\" from t where a = :1", rewritten.sql());
        assertEquals(1, rewritten.parameters());
    }

    @Test
    void leavesCommentsAlone() throws SQLException {
        OraSqlRewriter.Rewritten rewritten = OraSqlRewriter.rewrite(
                "select a -- really? yes\nfrom t /* and here? also */ where a = ?");
        assertEquals("select a -- really? yes\nfrom t /* and here? also */ where a = :1",
                rewritten.sql());
        assertEquals(1, rewritten.parameters());
    }

    /**
     * Oracle's alternative quoting, where the delimiter follows the {@code q'}
     * and a bracket closes with its mirror image. Inside it, quotes and
     * question marks are text.
     */
    @Test
    void understandsAlternativeQuoting() throws SQLException {
        OraSqlRewriter.Rewritten rewritten =
                OraSqlRewriter.rewrite("select q'[it's ? here]' from dual where a = ?");
        assertEquals("select q'[it's ? here]' from dual where a = :1", rewritten.sql());
        assertEquals(1, rewritten.parameters());
    }

    @Test
    void saysSoWhenALiteralIsNotClosed() {
        SQLException failure = assertThrows(SQLException.class,
                () -> OraSqlRewriter.rewrite("select 'open from dual"));
        assertEquals(true, failure.getMessage().contains("unterminated"));
    }
}
