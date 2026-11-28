package space.seclume.field;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import space.seclume.field.EncryptedColumn.Mode;

/**
 * Moves the encrypted columns of a table onto the ring's primary key, while
 * the application keeps using it: in batches, one transaction each, resumable
 * from where it stopped, and without overwriting a value that changed in the
 * meantime.
 *
 * <pre>{@code
 * ColumnRotation rotation = ColumnRotation.builder(keys)
 *         .table("patient").id("id")
 *         .column("ssn", "patient.ssn", Mode.DETERMINISTIC, Context.NONE)
 *         .column("diagnosis", "patient.diagnosis", Mode.RANDOMIZED, Context.ROW_ID)
 *         .batchSize(500)
 *         .build();
 * ColumnRotation.Progress done = rotation.run(connection);
 * ColumnRotation.Census left = rotation.census(connection);   // all under the primary key?
 * }</pre>
 *
 * <p><b>How.</b> Rows are read in the order of {@code id} - which must be
 * unique, and is best the primary key - {@code batchSize} at a time, after the
 * last {@code id} of the batch before ({@code where id > ?}, portable across the
 * four databases, no offsets). A value under another key than the primary is
 * decrypted into locked native memory, encrypted under the primary and written
 * back with {@code update ... where id = ? and column = <the old value>}: a row
 * the application changed in the meantime is not overwritten but counted as a
 * conflict - and was written under the primary key anyway, since the
 * application writes with the same ring. A value already under the primary key
 * is left alone, so a second run finds nothing to do and a stopped run picks
 * up at {@link Progress#lastId()} ({@link Builder#after}).
 *
 * <p>The columns must compare by value in a {@code where} - {@code bytea},
 * {@code varbinary}, {@code raw}; not an Oracle {@code BLOB}.
 */
public final class ColumnRotation {

    /** What a column's values were bound to when they were written. */
    public enum Context {
        /** Nothing: {@link EncryptedColumn#encrypt(java.lang.foreign.MemorySegment)}. */
        NONE,
        /**
         * The row's {@code id} - a value copied into another row is refused
         * there. Encoded as {@link #rowIdContext}: binary ids as their bytes,
         * decimals without trailing zeros, everything else as its text in
         * UTF-8 - what the application binds when it writes.
         */
        ROW_ID
    }

    /**
     * How far it got.
     *
     * @param rows      rows read
     * @param rotated   values moved onto the primary key
     * @param current   values already under it
     * @param conflicts values that changed while they were being moved - left as the application wrote them
     * @param lastId    the {@code id} of the last row read: where a stopped run continues
     * @param done      whether the end of the table was reached
     * @param unreadable values that did not open with the ring - tampered with, damaged, or
     *                   under a key no longer in it - left as they are
     * @param unreadableIds the row ids of the first {@value #IDS_KEPT} of them, to look at
     */
    public record Progress(long rows, long rotated, long current, long conflicts, Object lastId,
            boolean done, long unreadable, List<Object> unreadableIds) {

        /** How many ids of unreadable rows a progress keeps. */
        public static final int IDS_KEPT = 100;

        public Progress {
            unreadableIds = List.copyOf(unreadableIds);
        }

        Progress plus(Progress batch) {
            List<Object> ids = new ArrayList<>(unreadableIds);
            for (Object one : batch.unreadableIds) {
                if (ids.size() < IDS_KEPT) {
                    ids.add(one);
                }
            }
            return new Progress(rows + batch.rows, rotated + batch.rotated, current + batch.current,
                    conflicts + batch.conflicts, batch.lastId == null ? lastId : batch.lastId,
                    batch.done, unreadable + batch.unreadable, ids);
        }
    }

    /**
     * Which key each column's values are under.
     *
     * @param keys    per column, the count per key number; {@code null} values are not counted
     * @param primary the ring's primary key
     */
    public record Census(Map<String, Map<Integer, Long>> keys, int primary) {

        /**
         * Before a key leaves the ring: refused while any value is still
         * counted under it. Nothing stopped a key from being taken out with
         * values under it, and those were lost for good.
         *
         * @throws IllegalStateException naming the columns that still hold values under it
         */
        public void requireNoneUnder(int key) {
            List<String> holding = new ArrayList<>();
            for (Map.Entry<String, Map<Integer, Long>> column : keys.entrySet()) {
                Long count = column.getValue().get(key);
                if (count != null && count > 0) {
                    holding.add(column.getKey() + " (" + count + ")");
                }
            }
            if (key == primary) {
                throw new IllegalStateException("key " + key + " is the primary - make another "
                        + "one primary and rotate first");
            }
            if (!holding.isEmpty()) {
                throw new IllegalStateException("key " + key + " still has values under it in "
                        + String.join(", ", holding) + " - rotate them first, or they are lost "
                        + "with the key");
            }
        }

        /** Values under another key than the primary - what a rotation still has to do. */
        public long remaining() {
            long remaining = 0;
            for (Map<Integer, Long> column : keys.values()) {
                for (Map.Entry<Integer, Long> key : column.entrySet()) {
                    if (key.getKey() != primary) {
                        remaining += key.getValue();
                    }
                }
            }
            return remaining;
        }
    }

    private record Column(String sql, EncryptedColumn column, Context context) {
    }

    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_][A-Za-z0-9_$]*(\\.[A-Za-z_][A-Za-z0-9_$]*)?");

    private final FieldKeys keys;
    private final String table;
    private final String id;
    private final List<Column> columns;
    private final int batchSize;
    private final Object after;
    private final Consumer<Progress> listener;

    private ColumnRotation(Builder builder) {
        this.keys = builder.keys;
        this.table = builder.table;
        this.id = builder.id;
        this.columns = List.copyOf(builder.columns);
        this.batchSize = builder.batchSize;
        this.after = builder.after;
        this.listener = builder.listener;
    }

    /** A rotation with the ring {@code keys}, onto its primary key. */
    public static Builder builder(FieldKeys keys) {
        return new Builder(keys);
    }

    /**
     * Rotates to the end of the table, one transaction per batch, and returns
     * what it did. The connection's auto-commit is restored afterwards.
     */
    public Progress run(Connection connection) throws SQLException {
        Progress total = new Progress(0, 0, 0, 0, after, false, 0, List.of());
        Object from = after;
        while (true) {
            Progress batch = step(connection, from);
            total = total.plus(batch);
            if (listener != null) {
                listener.accept(total);
            }
            if (batch.done()) {
                return total;
            }
            from = batch.lastId();
        }
    }

    /**
     * One batch: the rows after {@code after} (all of them from the start when
     * {@code null}), in one transaction.
     */
    public Progress step(Connection connection, Object after) throws SQLException {
        boolean autoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        try {
            Progress batch = batch(connection, after);
            connection.commit();
            return batch;
        } catch (SQLException | RuntimeException e) {
            try {
                connection.rollback();
            } catch (SQLException rollback) {
                e.addSuppressed(rollback);
            }
            throw e;
        } finally {
            connection.setAutoCommit(autoCommit);
        }
    }

    private Progress batch(Connection connection, Object after) throws SQLException {
        StringBuilder sql = new StringBuilder("select ").append(id);
        for (Column column : columns) {
            sql.append(", ").append(column.sql());
        }
        sql.append(" from ").append(table);
        if (after != null) {
            sql.append(" where ").append(id).append(" > ?");
        }
        sql.append(" order by ").append(id);
        List<Object> ids = new ArrayList<>();
        List<byte[][]> values = new ArrayList<>();
        try (PreparedStatement select = connection.prepareStatement(sql.toString())) {
            select.setMaxRows(batchSize);
            select.setFetchSize(batchSize);
            if (after != null) {
                select.setObject(1, after);
            }
            try (ResultSet rows = select.executeQuery()) {
                while (rows.next() && ids.size() < batchSize) {
                    ids.add(rows.getObject(1));
                    byte[][] row = new byte[columns.size()][];
                    for (int c = 0; c < columns.size(); c++) {
                        row[c] = rows.getBytes(c + 2); // seclume-allow: ciphertext, not a secret
                    }
                    values.add(row);
                }
            }
        }
        long rotated = 0;
        long current = 0;
        long conflicts = 0;
        long unreadable = 0;
        List<Object> unreadableIds = new ArrayList<>();
        for (int r = 0; r < ids.size(); r++) {
            Object rowId = ids.get(r);
            byte[][] row = values.get(r);
            List<Integer> changed = new ArrayList<>();
            byte[][] fresh = new byte[columns.size()][];
            for (int c = 0; c < columns.size(); c++) {
                if (row[c] == null) {
                    continue;
                }
                Column column = columns.get(c);
                if (column.column().needsReencryption(row[c])) {
                    try {
                        fresh[c] = column.column().reencrypt(row[c], context(column, rowId));
                    } catch (FieldEncryptionException doesNotOpen) {
                        // One value that does not open - tampered with, damaged,
                        // under a key gone from the ring - stopped the whole
                        // rotation. It is left as it is and counted, with its id.
                        unreadable++;
                        if (unreadableIds.size() < Progress.IDS_KEPT) { // mutation-equivalent: the batch is added to the run with Progress.plus, which keeps IDS_KEPT as well
                            unreadableIds.add(rowId);
                        }
                        continue;
                    }
                    changed.add(c);
                } else {
                    current++;
                }
            }
            if (changed.isEmpty()) {
                continue;
            }
            StringBuilder update = new StringBuilder("update ").append(table).append(" set ");
            for (int i = 0; i < changed.size(); i++) {
                update.append(i == 0 ? "" : ", ").append(columns.get(changed.get(i)).sql()).append(" = ?");
            }
            update.append(" where ").append(id).append(" = ?");
            for (int c : changed) {
                update.append(" and ").append(columns.get(c).sql()).append(" = ?");
            }
            try (PreparedStatement statement = connection.prepareStatement(update.toString())) {
                int p = 1;
                for (int c : changed) {
                    statement.setBytes(p++, fresh[c]);
                }
                statement.setObject(p++, rowId);
                for (int c : changed) {
                    statement.setBytes(p++, row[c]);
                }
                if (statement.executeUpdate() == 1) {
                    rotated += changed.size();
                } else {
                    conflicts += changed.size();
                }
            }
        }
        Object last = ids.isEmpty() ? after : ids.get(ids.size() - 1);
        return new Progress(ids.size(), rotated, current, conflicts, last, ids.size() < batchSize,
                unreadable, unreadableIds);
    }

    private static byte[] context(Column column, Object rowId) {
        if (column.context() == Context.NONE) {
            return new byte[0];
        }
        return rowIdContext(rowId);
    }

    /**
     * A row id as a context. String.valueOf made a byte[] id (RAW, BINARY, a
     * UUID as bytes) its identity in memory - "[B@1a2b..." - and no value
     * opened; a BigDecimal was 17 or 17.0 depending on the driver. Binary ids
     * are their bytes, decimals are stripped of trailing zeros, and the rest
     * is its text as before - so what was written keeps opening.
     */
    public static byte[] rowIdContext(Object rowId) {
        if (rowId instanceof byte[] bytes) {
            return bytes.clone();
        }
        if (rowId instanceof java.math.BigDecimal decimal) {
            String plain = decimal.signum() == 0 ? "0" : decimal.stripTrailingZeros().toPlainString();
            return plain.getBytes(StandardCharsets.UTF_8); // seclume-allow: a row id, not a secret
        }
        return String.valueOf(rowId).getBytes(StandardCharsets.UTF_8); // seclume-allow: a row id, not a secret
    }

    /** Counts, per column, the values under each key. Reads every row once; changes nothing. */
    public Census census(Connection connection) throws SQLException {
        Map<String, Map<Integer, Long>> counts = new LinkedHashMap<>();
        StringBuilder sql = new StringBuilder("select ");
        for (int c = 0; c < columns.size(); c++) {
            sql.append(c == 0 ? "" : ", ").append(columns.get(c).sql());
            counts.put(columns.get(c).sql(), new TreeMap<>());
        }
        sql.append(" from ").append(table);
        try (PreparedStatement select = connection.prepareStatement(sql.toString());
             ResultSet rows = select.executeQuery()) {
            while (rows.next()) {
                for (int c = 0; c < columns.size(); c++) {
                    byte[] value = rows.getBytes(c + 1); // seclume-allow: ciphertext, not a secret
                    if (value != null) {
                        counts.get(columns.get(c).sql()).merge(columns.get(c).column().keyId(value),
                                1L, Long::sum);
                    }
                }
            }
        }
        Map<String, Map<Integer, Long>> frozen = new LinkedHashMap<>();
        counts.forEach((name, perKey) -> frozen.put(name, Map.copyOf(perKey)));
        return new Census(Map.copyOf(frozen), keys.primary());
    }

    /** Builds a {@link ColumnRotation}. */
    public static final class Builder {

        private final FieldKeys keys;
        private String table;
        private String id;
        private final List<Column> columns = new ArrayList<>();
        private int batchSize = 500;
        private Object after;
        private Consumer<Progress> listener;

        private Builder(FieldKeys keys) {
            if (keys == null) {
                throw new IllegalArgumentException("a rotation needs the key ring");
            }
            this.keys = keys;
        }

        /** The table, optionally with its schema - {@code orders.patient}. */
        public Builder table(String name) {
            this.table = identifier(name, "table");
            return this;
        }

        /** The column rows are ordered and resumed by: unique, best the primary key. */
        public Builder id(String name) {
            this.id = identifier(name, "id column");
            return this;
        }

        /**
         * An encrypted column: its name in the table, the name its key is
         * derived from ({@link FieldKeys#column}), its mode, and its context.
         */
        public Builder column(String sqlName, String keyName, Mode mode, Context context) {
            identifier(sqlName, "column");
            if (keyName == null || keyName.isBlank() || mode == null || context == null) {
                throw new IllegalArgumentException("a column needs its key name, its mode and its context");
            }
            for (Column column : columns) {
                if (column.sql().equalsIgnoreCase(sqlName)) {
                    throw new IllegalArgumentException("the column " + sqlName + " is there twice");
                }
            }
            columns.add(new Column(sqlName, keys.column(keyName, mode), context));
            return this;
        }

        /** Rows per transaction, 1 to 100000; 500 by default. */
        public Builder batchSize(int rows) {
            if (rows < 1 || rows > 100_000) {
                throw new IllegalArgumentException("a batch is 1 to 100000 rows, not " + rows);
            }
            this.batchSize = rows;
            return this;
        }

        /** Continues after this {@code id} - a stopped run's {@link Progress#lastId()}. */
        public Builder after(Object lastId) {
            this.after = lastId;
            return this;
        }

        /** Told the running total after every batch - for a log line, a gauge, a progress bar. */
        public Builder listener(Consumer<Progress> listener) {
            this.listener = listener;
            return this;
        }

        public ColumnRotation build() {
            if (table == null || id == null || columns.isEmpty()) {
                throw new IllegalArgumentException("a rotation needs a table, its id column and at "
                        + "least one encrypted column");
            }
            for (Column column : columns) {
                if (column.sql().equalsIgnoreCase(id)) {
                    throw new IllegalArgumentException("the id column " + id + " cannot be an encrypted column");
                }
            }
            return new ColumnRotation(this);
        }

        private static String identifier(String name, String what) {
            if (name == null || !IDENTIFIER.matcher(name).matches()) {
                throw new IllegalArgumentException("a " + what + " is a plain SQL identifier "
                        + "(letters, digits, _ and $, optionally schema.name), not " + name);
            }
            return name;
        }
    }
}
