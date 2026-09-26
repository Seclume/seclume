package space.seclume;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Which statements may be trusted to have written nothing.
 *
 * <p>Only these are left alone when their answer is lost in auto-commit
 * mode; everything else is reported as a commit whose outcome is unknown. The
 * two ways of being wrong are not equal: calling a read a write costs a check
 * that finds nothing, calling a write a read gets it repeated. So most of the
 * cases below are about the second.
 */
class ReadOnlyStatementTest {

    @Test
    void plainReadsAreReads() {
        assertTrue(TransactionResolutionUnknownException.onlyReads("select 1"));
        assertTrue(TransactionResolutionUnknownException.onlyReads(
                "SELECT id FROM customer WHERE name = ?"));
        assertTrue(TransactionResolutionUnknownException.onlyReads("show tables"));
        assertTrue(TransactionResolutionUnknownException.onlyReads("explain select 1"));
        assertTrue(TransactionResolutionUnknownException.onlyReads("values (1), (2)"));
        assertTrue(TransactionResolutionUnknownException.onlyReads(
                "with recent as (select * from orders) select count(*) from recent"));
    }

    /** What an ORM or a hand puts in front of the first keyword. */
    @Test
    void commentsAndParenthesesAreLookedPast() {
        assertTrue(TransactionResolutionUnknownException.onlyReads("  (select 1) union (select 2)"));
        assertTrue(TransactionResolutionUnknownException.onlyReads("/* page 3 */ select 1"));
        assertTrue(TransactionResolutionUnknownException.onlyReads("-- report\nselect 1"));
        assertFalse(TransactionResolutionUnknownException.onlyReads("/* select */ delete from t"));
    }

    @Test
    void writesAreWrites() {
        assertFalse(TransactionResolutionUnknownException.onlyReads("insert into t values (1)"));
        assertFalse(TransactionResolutionUnknownException.onlyReads("update t set n = 2"));
        assertFalse(TransactionResolutionUnknownException.onlyReads("delete from t"));
        assertFalse(TransactionResolutionUnknownException.onlyReads("merge into t using s on (1=1)"));
        // PostgreSQL's insert ... returning is usually run through
        // executeQuery, which is why the method is not what decides.
        assertFalse(TransactionResolutionUnknownException.onlyReads(
                "insert into t (n) values (1) returning id"));
    }

    /** The reads that are not, and the reason each one is here. */
    @Test
    void theTrapsLookLikeReadsAndAreNot() {
        // Creates a table on PostgreSQL and SQL Server, writes a file on MySQL.
        assertFalse(TransactionResolutionUnknownException.onlyReads(
                "select * into archive from orders"));
        assertFalse(TransactionResolutionUnknownException.onlyReads(
                "select * from orders into outfile '/tmp/x'"));
        // A data-modifying common table expression starts with "with" too.
        assertFalse(TransactionResolutionUnknownException.onlyReads(
                "with gone as (delete from orders returning *) select count(*) from gone"));
        assertFalse(TransactionResolutionUnknownException.onlyReads(
                "with x as (select 1) insert into t select * from x"));
    }

    /** Anything not recognised may write, and is treated so. */
    @Test
    void theUnknownIsNotARead() {
        assertFalse(TransactionResolutionUnknownException.onlyReads("call archive_orders()"));
        assertFalse(TransactionResolutionUnknownException.onlyReads("exec archive_orders"));
        assertFalse(TransactionResolutionUnknownException.onlyReads(
                "begin archive_orders; end;"));
        assertFalse(TransactionResolutionUnknownException.onlyReads("{call archive_orders}"));
        assertFalse(TransactionResolutionUnknownException.onlyReads(""));
    }

    /**
     * Whole words only - {@code into} inside a name is not {@code into}.
     *
     * <p>Otherwise a column called {@code intolerance} would turn every read
     * of it into a write. That would only cost a needless check, which is why
     * the rule errs that way elsewhere, but it is easy to get right here.
     */
    @Test
    void aWordInsideANameIsNotTheWord() {
        assertTrue(TransactionResolutionUnknownException.onlyReads(
                "select intolerance, updated_at from patient"));
    }

    /**
     * A function somebody wrote may write, with a table or without one.
     *
     * <p>On PostgreSQL {@code select create_order(42)} is how a function that
     * does something is called, and in auto-commit whatever it wrote is
     * committed. {@code select archive(id) from orders} does the same once
     * per row - the first version of this rule missed that one and said so;
     * it is covered now.
     */
    @Test
    void aFunctionSomebodyWroteMayWrite() {
        assertFalse(TransactionResolutionUnknownException.onlyReads("select create_order(42)"));
        assertFalse(TransactionResolutionUnknownException.onlyReads(
                "select archive(id) from orders"));
        assertFalse(TransactionResolutionUnknownException.onlyReads(
                "select app.archive(id) from orders"));
        assertFalse(TransactionResolutionUnknownException.onlyReads(
                "with o as (select id from orders) select archive(id) from o"));
    }

    /** Built-ins that do something are not on the pure list either. */
    @Test
    void builtInsWithSideEffectsMayWrite() {
        assertFalse(TransactionResolutionUnknownException.onlyReads(
                "select nextval('order_id')"));
        assertFalse(TransactionResolutionUnknownException.onlyReads(
                "SELECT pg_advisory_lock(7)"));
        assertFalse(TransactionResolutionUnknownException.onlyReads("select get_lock('x', 1)"));
    }

    /** And the everyday reads stay reads - otherwise every lost report would cry wolf. */
    @Test
    void pureBuiltInsAndGroupingAreReads() {
        assertTrue(TransactionResolutionUnknownException.onlyReads(
                "select count(*), max(total) from orders where status = ?"));
        assertTrue(TransactionResolutionUnknownException.onlyReads(
                "SELECT lower(name), coalesce(city, '-') FROM customer"));
        assertTrue(TransactionResolutionUnknownException.onlyReads("select now()"));
        assertTrue(TransactionResolutionUnknownException.onlyReads(
                "select row_number() over (order by id) from orders"));
        assertTrue(TransactionResolutionUnknownException.onlyReads("select (1 + 2) * 3"));
        assertTrue(TransactionResolutionUnknownException.onlyReads(
                "(select 1) union all (select 2)"));
        assertTrue(TransactionResolutionUnknownException.onlyReads(
                "select id from orders where id in (select order_id from lines)"));
        assertTrue(TransactionResolutionUnknownException.onlyReads(
                "select t.n from (select 1 as n) t join (select 1 as n) u using (n)"));
    }
}
