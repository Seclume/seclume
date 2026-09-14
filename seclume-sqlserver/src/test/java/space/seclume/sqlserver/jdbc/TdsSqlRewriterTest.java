package space.seclume.sqlserver.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * The rewrite from {@code ?} to {@code @P0}.
 *
 * <p>Worth its own test because the failure mode is quiet: a question mark
 * inside a literal that gets replaced does not produce an error, it produces a
 * statement that runs and returns the wrong thing.
 */
class TdsSqlRewriterTest {

    @Test
    void numbersThePlaceholdersInOrder() throws SQLException {
        TdsSqlRewriter.Rewritten result =
                TdsSqlRewriter.rewrite("select * from t where a = ? and b = ?");
        assertEquals("select * from t where a = @P0 and b = @P1", result.sql());
        assertEquals(2, result.parameters());
    }

    /** A question mark in a literal is text and stays text. */
    @Test
    void leavesLiteralsAlone() throws SQLException {
        TdsSqlRewriter.Rewritten result = TdsSqlRewriter.rewrite(
                "select 'was ist das?' as q, [odd?column] from t where a = ?");
        assertEquals("select 'was ist das?' as q, [odd?column] from t where a = @P0",
                result.sql());
        assertEquals(1, result.parameters());
    }

    /** A doubled quote is an escaped one, not the end of the literal. */
    @Test
    void understandsDoubledQuotes() throws SQLException {
        TdsSqlRewriter.Rewritten result =
                TdsSqlRewriter.rewrite("select 'it''s a ?' where a = ?");
        assertEquals("select 'it''s a ?' where a = @P0", result.sql());
        assertEquals(1, result.parameters());
    }

    @Test
    void leavesCommentsAlone() throws SQLException {
        TdsSqlRewriter.Rewritten result = TdsSqlRewriter.rewrite(
                "select 1 -- really? yes\nwhere a = ? /* and b = ? */ and c = ?");
        assertEquals("select 1 -- really? yes\nwhere a = @P0 /* and b = ? */ and c = @P1",
                result.sql());
        assertEquals(2, result.parameters());
    }

    /** T-SQL block comments nest - the inner close does not end the outer. */
    @Test
    void countsNestedBlockComments() throws SQLException {
        TdsSqlRewriter.Rewritten result =
                TdsSqlRewriter.rewrite("select /* a /* b ? */ c ? */ 1 where x = ?");
        assertEquals("select /* a /* b ? */ c ? */ 1 where x = @P0", result.sql());
        assertEquals(1, result.parameters());
    }

    @Test
    void refusesAnUnterminatedLiteral() {
        SQLException failure = assertThrows(SQLException.class,
                () -> TdsSqlRewriter.rewrite("select 'open where a = ?"));
        assertEquals(true, failure.getMessage().contains("unterminated"));
    }
}
