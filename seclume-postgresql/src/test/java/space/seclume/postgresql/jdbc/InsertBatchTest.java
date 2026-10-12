package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/** Which inserts are taken apart for {@code rewriteBatchedInserts} - and which are left alone. */
class InsertBatchTest {

    @Test
    void aPlainInsertBecomesMultiRow() {
        InsertBatch shape = InsertBatch.parse("INSERT INTO t (a, b) VALUES (?, ?)");
        assertNotNull(shape);
        assertEquals(2, shape.parameters());
        assertEquals("INSERT INTO t (a, b) VALUES (?, ?), (?, ?), (?, ?)", shape.sql(3));
    }

    @Test
    void literalsAndFunctionsInTheTupleStay() {
        InsertBatch shape = InsertBatch.parse("insert into notes (id, note, at) values "
                + "(?, concat('a (?) ', ?), now())");
        assertNotNull(shape);
        assertEquals(2, shape.parameters());
        assertEquals("insert into notes (id, note, at) values (?, concat('a (?) ', ?), now()), "
                + "(?, concat('a (?) ', ?), now())", shape.sql(2));
    }

    @Test
    void onConflictWithoutPlaceholdersIsKept() {
        InsertBatch shape = InsertBatch.parse(
                "insert into t (id) values (?) on conflict (id) do update set n = t.n + 1");
        assertNotNull(shape);
        assertEquals("insert into t (id) values (?), (?) on conflict (id) do update "
                + "set n = t.n + 1", shape.sql(2));
        assertNotNull(InsertBatch.parse("/* c */ INSERT INTO t VALUES (?) ON CONFLICT DO NOTHING"));
    }

    @Test
    void anythingElseIsDeclined() {
        for (String sql : new String[] {
            "insert into t select ?",
            "with x as (select 1) insert into t values (?)",
            "insert into t values (?) returning id",
            "insert into t values (?) on conflict do nothing returning id",
            "insert into t values (?) on conflict (id) do update set n = ?",
            "insert into t values (?), (?)",
            "insert into t values ($1)",
            "insert into t values (?, $$a (b) c$$)",
            "insert into t values (?, E'a\\'b')",
            "insert into t default values",
            "update t set a = ?",
            "insert into t values (?);",
            "insert into t values (1)",
        }) {
            assertNull(InsertBatch.parse(sql), sql);
        }
    }
}
