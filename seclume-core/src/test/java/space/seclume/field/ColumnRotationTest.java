package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.field.ColumnRotation.Context;
import space.seclume.field.ColumnRotation.Progress;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.secret.SecretScope;

/**
 * The rotation job against a table in memory - a JDBC stand-in that speaks
 * exactly the SQL the job writes, and can change a row behind its back. The
 * same job against the four real databases is {@code EncryptedColumnContract}.
 */
@Isolated
class ColumnRotationTest {

    private static final byte[] KEY1 = new byte[32];
    private static final byte[] KEY2 = new byte[32];

    static {
        for (int i = 0; i < 32; i++) {
            KEY1[i] = (byte) i;
            KEY2[i] = (byte) (0x80 + i);
        }
    }

    /** id -> {secret, ssn}; the order of a TreeMap is the order of the id. */
    static final class Table {
        final TreeMap<Integer, byte[][]> rows = new TreeMap<>();
        final List<String> statements = new ArrayList<>();
        int commits;
        int rollbacks;
        boolean autoCommit = true;
        /** Called with the ids a select returned, before the job updates any of them. */
        Consumer<List<Integer>> afterSelect = ids -> { };
        RuntimeException failUpdate;
    }

    private static FieldKeys ring(int primary, byte[]... keys) {
        FieldKeys.Builder builder = FieldKeys.builder();
        for (int i = 0; i < keys.length; i++) {
            builder.key(i + 1, FieldEncryptionTest.provider(keys[i]));
        }
        return builder.primary(primary).build();
    }

    private static MemorySegment text(String value) {
        return MemorySegment.ofArray(value.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] context(int id) {
        return Integer.toString(id).getBytes(StandardCharsets.US_ASCII);
    }

    private static String read(EncryptedColumn column, byte[] value, byte[] context) {
        try (SecretScope out = SecretScope.allocate(256)) {
            out.length(column.decrypt(value, context, out.segment()));
            return new String(out.secret().toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
        }
    }

    /** Rows 1..n under key 1; every third ssn null. */
    private static Table table(int n) {
        Table table = new Table();
        try (FieldKeys one = ring(1, KEY1)) {
            EncryptedColumn secret = one.column("zl.secret", Mode.RANDOMIZED);
            EncryptedColumn ssn = one.column("zl.ssn", Mode.DETERMINISTIC);
            for (int id = 1; id <= n; id++) {
                table.rows.put(id, new byte[][] {secret.encrypt(text("secret " + id), context(id)),
                        id % 3 == 0 ? null : ssn.encrypt(text("ssn " + id))});
            }
        }
        return table;
    }

    private static ColumnRotation rotation(FieldKeys keys, int batch, Object after,
            Consumer<Progress> listener) {
        return ColumnRotation.builder(keys).table("zl_patient").id("id")
                .column("secret", "zl.secret", Mode.RANDOMIZED, Context.ROW_ID)
                .column("ssn", "zl.ssn", Mode.DETERMINISTIC, Context.NONE)
                .batchSize(batch).after(after).listener(listener).build();
    }

    @Test
    void everyValueEndsUpUnderThePrimaryAndReadsAsBefore() throws SQLException {
        Table table = table(23);
        List<Progress> seen = new ArrayList<>();
        try (FieldKeys both = ring(2, KEY1, KEY2)) {
            ColumnRotation rotation = rotation(both, 5, null, seen::add);
            ColumnRotation.Census before = rotation.census(connection(table));
            assertEquals(Map.of(1, 23L), before.keys().get("secret"));
            assertEquals(Map.of(1, 16L), before.keys().get("ssn"));
            assertEquals(39, before.remaining());

            Progress done = rotation.run(connection(table));
            assertEquals(23, done.rows());
            assertEquals(39, done.rotated());
            assertEquals(0, done.current());
            assertEquals(0, done.conflicts());
            assertEquals(23, done.lastId());
            assertTrue(done.done());
            assertEquals(5, seen.size(), "a batch of 5 at a time, the last one short");
            assertEquals(5, table.commits);
            assertTrue(table.autoCommit, "auto-commit restored");

            ColumnRotation.Census after = rotation.census(connection(table));
            assertEquals(Map.of(2, 23L), after.keys().get("secret"));
            assertEquals(0, after.remaining());
        }
        try (FieldKeys two = ring(2, new byte[32], KEY2)) {
            // Key 1 replaced by nonsense: everything reads under key 2 alone.
            EncryptedColumn secret = two.column("zl.secret", Mode.RANDOMIZED);
            EncryptedColumn ssn = two.column("zl.ssn", Mode.DETERMINISTIC);
            for (Map.Entry<Integer, byte[][]> row : table.rows.entrySet()) {
                int id = row.getKey();
                assertEquals("secret " + id, read(secret, row.getValue()[0], context(id)));
                if (id % 3 != 0) {
                    assertEquals("ssn " + id, read(ssn, row.getValue()[1], new byte[0]));
                    assertArrayEquals(ssn.searchTerms(text("ssn " + id)).get(0), row.getValue()[1],
                            "the deterministic value is the one a search under key 2 finds");
                }
            }
        }
    }

    @Test
    void aSecondRunHasNothingToDo() throws SQLException {
        Table table = table(12);
        try (FieldKeys both = ring(2, KEY1, KEY2)) {
            rotation(both, 4, null, null).run(connection(table));
            table.statements.clear();
            Progress again = rotation(both, 4, null, null).run(connection(table));
            assertEquals(0, again.rotated());
            assertEquals(20, again.current());
            assertFalse(table.statements.stream().anyMatch(s -> s.startsWith("update")),
                    "nothing written the second time");
        }
    }

    @Test
    void aStoppedRunContinuesWhereItStopped() throws SQLException {
        Table table = table(17);
        try (FieldKeys both = ring(2, KEY1, KEY2)) {
            ColumnRotation first = rotation(both, 6, null, null);
            Progress one = first.step(connection(table), null);
            assertEquals(6, one.rows());
            assertEquals(6, one.lastId());
            assertFalse(one.done());
            assertEquals(29 - 6 - 4, first.census(connection(table)).remaining());
            Progress rest = rotation(both, 6, one.lastId(), null).run(connection(table));
            assertEquals(11, rest.rows());
            assertEquals(0, rotation(both, 6, null, null).census(connection(table)).remaining());
            assertTrue(table.statements.stream().anyMatch(s -> s.contains("where id > ?")));
        }
    }

    @Test
    void aValueTheApplicationChangedMeanwhileIsNotOverwritten() throws SQLException {
        Table table = table(9);
        try (FieldKeys both = ring(2, KEY1, KEY2)) {
            EncryptedColumn secret = both.column("zl.secret", Mode.RANDOMIZED);
            byte[] written = secret.encrypt(text("changed by the application"), context(4));
            table.afterSelect = ids -> {
                if (ids.contains(4)) {
                    table.rows.get(4)[0] = written;
                }
            };
            Progress done = rotation(both, 5, null, null).run(connection(table));
            assertEquals(2, done.conflicts(), "row 4: its secret and its ssn, in one update");
            assertArrayEquals(written, table.rows.get(4)[0], "the application's write stands");
            assertEquals("changed by the application", read(secret, table.rows.get(4)[0], context(4)));
            // Its ssn is still under key 1 - the next run moves it.
            ColumnRotation.Census left = rotation(both, 5, null, null).census(connection(table));
            assertEquals(1, left.remaining());
            table.afterSelect = ids -> { };
            assertEquals(1, rotation(both, 5, null, null).run(connection(table)).rotated());
        }
    }

    @Test
    void aFailingBatchIsRolledBack() {
        Table table = table(6);
        table.failUpdate = new IllegalStateException("the database went away");
        try (FieldKeys both = ring(2, KEY1, KEY2)) {
            assertThrows(IllegalStateException.class,
                    () -> rotation(both, 10, null, null).run(connection(table)));
            assertEquals(1, table.rollbacks);
            assertEquals(0, table.commits);
            assertTrue(table.autoCommit);
        }
    }

    @Test
    void anEmptyTableIsDoneAtOnce() throws SQLException {
        Table table = new Table();
        try (FieldKeys both = ring(2, KEY1, KEY2)) {
            Progress done = rotation(both, 10, null, null).run(connection(table));
            assertEquals(0, done.rows());
            assertTrue(done.done());
            assertEquals(0, rotation(both, 10, null, null).census(connection(table)).remaining());
        }
    }

    @Test
    void exactlyOneBatchFullStillEndsCleanly() throws SQLException {
        Table table = table(10);
        try (FieldKeys both = ring(2, KEY1, KEY2)) {
            List<Progress> seen = new ArrayList<>();
            rotation(both, 5, null, seen::add).run(connection(table));
            assertEquals(3, seen.size(), "5, 5 and an empty one that says it is done");
            assertTrue(seen.get(2).done());
            assertEquals(10, seen.get(2).lastId());
        }
    }

    @Test
    void whatCannotBeSqlIsRefused() {
        try (FieldKeys both = ring(2, KEY1, KEY2)) {
            for (String wrong : List.of("", "1table", "t; drop table x", "t--", "a.b.c", "t x")) {
                assertThrows(IllegalArgumentException.class,
                        () -> ColumnRotation.builder(both).table(wrong), wrong);
                assertThrows(IllegalArgumentException.class,
                        () -> ColumnRotation.builder(both).id(wrong), wrong);
                assertThrows(IllegalArgumentException.class, () -> ColumnRotation.builder(both)
                        .column(wrong, "k", Mode.RANDOMIZED, Context.NONE), wrong);
            }
            ColumnRotation.builder(both).table("orders.zl_patient").id("id_$1");
            assertThrows(IllegalArgumentException.class, () -> ColumnRotation.builder(both).build());
            assertThrows(IllegalArgumentException.class, () -> ColumnRotation.builder(both)
                    .table("t").id("id").column("id", "k", Mode.RANDOMIZED, Context.NONE).build());
            assertThrows(IllegalArgumentException.class, () -> ColumnRotation.builder(both)
                    .table("t").id("id").column("a", "k", Mode.RANDOMIZED, Context.NONE)
                    .column("A", "k2", Mode.RANDOMIZED, Context.NONE));
            assertThrows(IllegalArgumentException.class, () -> ColumnRotation.builder(both).batchSize(0));
            assertThrows(IllegalArgumentException.class, () -> ColumnRotation.builder(null));
        }
    }

    // ------------------------------------------------------- the stand-in

    private static final Pattern SELECT = Pattern.compile(
            "select id, secret, ssn from zl_patient( where id > \\?)? order by id");
    private static final Pattern CENSUS = Pattern.compile("select secret, ssn from zl_patient");
    private static final Pattern UPDATE = Pattern.compile(
            "update zl_patient set (.+) where id = \\?((?: and \\w+ = \\?)+)");

    private static Connection connection(Table table) {
        return (Connection) Proxy.newProxyInstance(ColumnRotationTest.class.getClassLoader(),
                new Class<?>[] {Connection.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getAutoCommit" -> table.autoCommit;
                    case "setAutoCommit" -> {
                        table.autoCommit = (Boolean) args[0];
                        yield null;
                    }
                    case "commit" -> {
                        table.commits++;
                        yield null;
                    }
                    case "rollback" -> {
                        table.rollbacks++;
                        yield null;
                    }
                    case "prepareStatement" -> statement(table, (String) args[0]);
                    case "close" -> null;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static PreparedStatement statement(Table table, String sql) {
        table.statements.add(sql);
        Object[] parameters = new Object[16];
        int[] maxRows = {Integer.MAX_VALUE};
        return (PreparedStatement) Proxy.newProxyInstance(ColumnRotationTest.class.getClassLoader(),
                new Class<?>[] {PreparedStatement.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "setMaxRows" -> {
                        maxRows[0] = (Integer) args[0];
                        yield null;
                    }
                    case "setFetchSize", "close" -> null;
                    case "setObject", "setBytes" -> {
                        parameters[(Integer) args[0]] = args[1];
                        yield null;
                    }
                    case "executeQuery" -> query(table, sql, parameters, maxRows[0]);
                    case "executeUpdate" -> update(table, sql, parameters);
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static ResultSet query(Table table, String sql, Object[] parameters, int maxRows) {
        List<Object[]> result = new ArrayList<>();
        Matcher select = SELECT.matcher(sql);
        if (select.matches()) {
            Map<Integer, byte[][]> rows = select.group(1) == null ? table.rows
                    : table.rows.tailMap((Integer) parameters[1], false);
            List<Integer> ids = new ArrayList<>();
            for (Map.Entry<Integer, byte[][]> row : rows.entrySet()) {
                if (result.size() == maxRows) {
                    break;
                }
                result.add(new Object[] {row.getKey(), copy(row.getValue()[0]), copy(row.getValue()[1])});
                ids.add(row.getKey());
            }
            table.afterSelect.accept(ids);
        } else if (CENSUS.matcher(sql).matches()) {
            for (byte[][] row : table.rows.values()) {
                result.add(new Object[] {copy(row[0]), copy(row[1])});
            }
        } else {
            throw new AssertionError("unexpected SQL: " + sql);
        }
        int[] at = {-1};
        return (ResultSet) Proxy.newProxyInstance(ColumnRotationTest.class.getClassLoader(),
                new Class<?>[] {ResultSet.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "next" -> ++at[0] < result.size();
                    case "getObject" -> result.get(at[0])[(Integer) args[0] - 1];
                    case "getBytes" -> result.get(at[0])[(Integer) args[0] - 1];
                    case "close" -> null;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static int update(Table table, String sql, Object[] parameters) {
        if (table.failUpdate != null) {
            throw table.failUpdate;
        }
        Matcher update = UPDATE.matcher(sql);
        if (!update.matches()) {
            throw new AssertionError("unexpected SQL: " + sql);
        }
        List<String> set = new ArrayList<>();
        for (String part : update.group(1).split(", ")) {
            set.add(part.replace(" = ?", ""));
        }
        List<String> where = new ArrayList<>();
        for (String part : update.group(2).trim().split(" and ")) {
            if (!part.isBlank()) {
                where.add(part.replace("and ", "").replace(" = ?", "").trim());
            }
        }
        assertEquals(set, where, "the old values of exactly the columns it sets");
        int id = (Integer) parameters[set.size() + 1];
        byte[][] row = table.rows.get(id);
        for (int i = 0; i < where.size(); i++) {
            int column = where.get(i).equals("secret") ? 0 : 1;
            if (!Arrays.equals(row[column], (byte[]) parameters[set.size() + 2 + i])) {
                return 0;
            }
        }
        for (int i = 0; i < set.size(); i++) {
            row[set.get(i).equals("secret") ? 0 : 1] = (byte[]) parameters[i + 1];
        }
        return 1;
    }

    private static byte[] copy(byte[] value) {
        return value == null ? null : value.clone();
    }
}
