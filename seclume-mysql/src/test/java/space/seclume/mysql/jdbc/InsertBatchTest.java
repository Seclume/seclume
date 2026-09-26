package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/** Which inserts are taken apart for multi-row batches - and, above all, which are not. */
class InsertBatchTest {

    @Test
    void aPlainInsertBecomesRowsOfTuples() {
        InsertBatch shape = InsertBatch.parse("INSERT INTO t (a, b) VALUES (?, ?)");
        assertNotNull(shape);
        assertEquals(2, shape.parameters());
        assertEquals("INSERT INTO t (a, b) VALUES (?, ?), (?, ?), (?, ?)", shape.sql(3));
    }

    @Test
    void functionsQuotedTextAndDuplicateKeyUpdateSurvive() {
        InsertBatch shape = InsertBatch.parse("insert into `values` (id, note, at) value "
                + "(?, concat('a (?) ', ?), now()) on duplicate key update note = values(note)");
        assertNotNull(shape);
        assertEquals(2, shape.parameters());
        assertEquals("insert into `values` (id, note, at) value (?, concat('a (?) ', ?), now()), "
                + "(?, concat('a (?) ', ?), now()) on duplicate key update note = values(note)",
                shape.sql(2));
        assertNotNull(InsertBatch.parse("REPLACE INTO t VALUES (?)"));
        assertNotNull(InsertBatch.parse("/* c */ INSERT IGNORE INTO t VALUES (?)"));
    }

    @Test
    void anythingLessCertainIsDeclined() {
        for (String sql : new String[] {
                "UPDATE t SET a = ?",
                "INSERT INTO t SET a = ?",
                "INSERT INTO t SELECT ? FROM dual",
                "INSERT INTO t VALUES (?), (?)",
                "INSERT INTO t VALUES (?) ON DUPLICATE KEY UPDATE a = ?",
                "INSERT INTO t VALUES (?);",
                "INSERT INTO t VALUES ('it\\'s', ?)",
                "INSERT INTO t VALUES (?) # comment",
                "INSERT INTO t (value) VALUES (?)",
                "INSERT INTO t VALUES (1)",
                "INSERT INTO t VALUES (?",
                "WITH x AS (SELECT 1) INSERT INTO t VALUES (?)"}) {
            assertNull(InsertBatch.parse(sql), sql);
        }
    }
}
