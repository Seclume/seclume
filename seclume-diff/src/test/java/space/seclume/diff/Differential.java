package space.seclume.diff;

import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Two drivers, one server, and every disagreement written down.
 *
 * <p>The idea behind this module in one line: <b>the vendor driver is the
 * oracle</b>. A hand-written test can only check what its author thought to
 * check, and the author of a driver is the worst person to guess what he got
 * wrong. pgjdbc, Connector/J, mssql-jdbc and ojdbc have each had twenty years
 * of other people finding out - so instead of asserting what a value should
 * be, this asserts that both drivers say the same thing, and a difference is a
 * finding in one of them.
 *
 * <h2>Four combinations, not one</h2>
 *
 * <p>A value is written through one driver and read through the other, and
 * then the other way round, and then each through itself. That matters because
 * writing and reading are separate codecs: a driver that encodes a
 * {@code numeric} one way and decodes its own encoding symmetrically agrees
 * with itself perfectly and with the server not at all. Only the crossed pairs
 * catch that.
 *
 * <h2>What is compared</h2>
 *
 * <p>For every column of every row: {@code getString}, the typed getter,
 * {@code wasNull}, and the {@link ResultSetMetaData} - type, type name,
 * precision, scale, nullability, class name. The metadata is included because
 * it is what Hibernate and Flyway read, and a driver that returns the right
 * value under the wrong type is a driver that breaks schema validation.
 *
 * <p>Differences that are <b>legitimate</b> - places where two drivers may
 * honestly disagree - are named one at a time in an allow-list with a reason.
 * A blanket tolerance would make the whole exercise decorative.
 */
final class Differential {

    /** One disagreement, in enough detail to act on. */
    record Finding(String column, String what, String wrote, String read,
                   String seclume, String vendor) {

        @Override
        public String toString() {
            return column + "." + what + "  [written by " + wrote + ", read by " + read + "]"
                    + "\n      seclume: " + describe(seclume)
                    + "\n      vendor : " + describe(vendor);
        }

        private static String describe(String value) {
            return value == null ? "<null>" : "\"" + value + "\"";
        }
    }

    /** A column of the table under test, and the values to put in it. */
    record Column(String name, String ddl, List<Object> values) {

        static Column of(String name, String ddl, Object... values) {
            return new Column(name, ddl, Arrays.asList(values));
        }
    }

    private final Connection seclume;
    private final Connection vendor;
    private final String table;
    private final List<Finding> findings = new ArrayList<>();
    /**
     * Findings already reported, so each one is said once.
     *
     * <p>Metadata does not change from row to row, so without this a single
     * wrong column type appears once per value per writer - sixteen times for
     * one fact, and a report nobody reads to the end. The value findings carry
     * their row number and so stay distinct on their own.
     */
    private final Set<String> reported = new LinkedHashSet<>();
    private final Set<String> allowed = new LinkedHashSet<>();

    Differential(Connection seclume, Connection vendor, String table) {
        this.seclume = seclume;
        this.vendor = vendor;
        this.table = table;
    }

    /**
     * Declares a difference legitimate.
     *
     * <p>{@code column.what} or just {@code what} for all columns. Every entry
     * needs a reason at the call site - an allow-list nobody can read is a
     * suppressed test with extra steps.
     */
    Differential allow(String key, String reason) {
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("an allowed difference needs a reason");
        }
        allowed.add(key);
        return this;
    }

    /**
     * Declares a difference <b>our</b> fault, and not fixed yet.
     *
     * <p>Kept apart from {@link #allow} on purpose. An allowed difference is
     * one where the two drivers may honestly disagree and seclume has
     * decided; a known defect is one where seclume is wrong and the fix has
     * not happened. Mixing the two turns the allow-list into a place where
     * bugs go to be forgotten, and the whole value of a differential run is
     * that it does not let that happen quietly.
     *
     * <p>Every entry names what is wrong and what it would take, so the list
     * reads as a backlog rather than as an excuse.
     */
    Differential knownDefect(String key, String whatIsWrong) {
        return allow(key, whatIsWrong);
    }

    List<Finding> findings() {
        return findings;
    }

    /** Runs every combination over every row and collects what differs. */
    void run(List<Column> columns) throws SQLException {
        create(columns);
        int rows = columns.stream().mapToInt(c -> c.values().size()).max().orElse(0);

        for (int row = 0; row < rows; row++) {
            for (Connection writer : List.of(seclume, vendor)) {
                String wrote = nameOf(writer);
                truncate();
                insert(writer, columns, row);
                compare(columns, wrote, row);
            }
        }
        compareCatalog(columns);
        drop();
    }

    /**
     * Reads the single row with both drivers and compares everything.
     *
     * <p>Twice over: once through a {@link Statement} and once through a
     * {@link PreparedStatement}. On MySQL and PostgreSQL those are different
     * wire protocols - text and binary - decoded by different code, and a
     * driver can be right in one and wrong in the other. Reading only one way
     * would leave half of every codec unexercised, and the half that is
     * usually wrong is the one the author used less.
     */
    private void compare(List<Column> columns, String wrote, int row) throws SQLException {
        String sql = "select " + String.join(", ", columns.stream().map(Column::name).toList())
                + " from " + table;
        compareThrough(columns, wrote, row, sql, false);
        compareThrough(columns, wrote, row, sql, true);
    }

    private void compareThrough(List<Column> columns, String wrote, int row, String sql,
            boolean prepared) throws SQLException {
        try (Statement a = prepared ? seclume.prepareStatement(sql) : seclume.createStatement();
             Statement b = prepared ? vendor.prepareStatement(sql) : vendor.createStatement();
             ResultSet mine = prepared ? ((PreparedStatement) a).executeQuery()
                     : a.executeQuery(sql);
             ResultSet theirs = prepared ? ((PreparedStatement) b).executeQuery()
                     : b.executeQuery(sql)) {

            boolean hasMine = mine.next();
            boolean hasTheirs = theirs.next();
            if (hasMine != hasTheirs) {
                findings.add(new Finding("<row>", "exists", wrote, "both",
                        String.valueOf(hasMine), String.valueOf(hasTheirs)));
                return;
            }
            if (!hasMine) {
                return;
            }

            for (int i = 1; i <= columns.size(); i++) {
                Column column = columns.get(i - 1);
                String how = prepared ? "prepared" : "text";
                compareValue(column, i, mine, theirs, wrote + "/" + how, row);
                compareMetaData(column, i, mine.getMetaData(), theirs.getMetaData(),
                        wrote + "/" + how);
            }
        }
    }

    /**
     * What the catalogue says about the table, through both drivers.
     *
     * <p>A different question from the one above and a more consequential
     * one: {@code ResultSetMetaData} describes one result, while
     * {@code DatabaseMetaData.getColumns} is what Hibernate's schema
     * validation and Flyway read before they will run at all. A driver can
     * return every value correctly and still be unusable because it describes
     * the schema differently from everyone else.
     *
     * <p>Compared once per table rather than per row - it does not depend on
     * the data.
     */
    private void compareCatalog(List<Column> columns) throws SQLException {
        List<String> fields = List.of("DATA_TYPE", "TYPE_NAME", "COLUMN_SIZE",
                "DECIMAL_DIGITS", "NUM_PREC_RADIX", "NULLABLE", "IS_NULLABLE",
                "ORDINAL_POSITION", "IS_AUTOINCREMENT");

        java.util.Map<String, java.util.Map<String, String>> mine = catalog(seclume, fields);
        java.util.Map<String, java.util.Map<String, String>> theirs = catalog(vendor, fields);

        for (Column column : columns) {
            String name = column.name();
            java.util.Map<String, String> a = mine.get(name);
            java.util.Map<String, String> b = theirs.get(name);
            if (a == null && b == null) {
                // Neither driver has a row for it. That is a question about
                // the catalogue's name matching - Oracle folds unquoted names
                // to upper case - and not a disagreement between the two, so
                // it is not a finding.
                continue;
            }
            if (a == null || b == null) {
                if (!isAllowed(name, "getColumns")) {
                    report(new Finding(name, "getColumns", "-", "both",
                            a == null ? "<missing>" : "<present>",
                            b == null ? "<missing>" : "<present>"));
                }
                continue;
            }
            for (String field : fields) {
                if (!equal(a.get(field), b.get(field))
                        && !isAllowed(name, "getColumns." + field)) {
                    report(new Finding(name, "getColumns." + field, "-", "both",
                            a.get(field), b.get(field)));
                }
            }
        }
    }

    private java.util.Map<String, java.util.Map<String, String>> catalog(Connection connection,
            List<String> fields) throws SQLException {
        java.util.Map<String, java.util.Map<String, String>> rows = new java.util.LinkedHashMap<>();
        try (ResultSet columns = connection.getMetaData()
                .getColumns(null, null, table, null)) {
            while (columns.next()) {
                java.util.Map<String, String> values = new java.util.LinkedHashMap<>();
                for (String field : fields) {
                    values.put(field, columns.getString(field));
                }
                rows.put(columns.getString("COLUMN_NAME"), values);
            }
        }
        return rows;
    }

    private void compareValue(Column column, int index, ResultSet mine, ResultSet theirs,
            String wrote, int row) throws SQLException {
        record Probe(String what, Read read) { }
        List<Probe> probes = List.of(
                new Probe("getString", rs -> rs.getString(index)),
                new Probe("getObject", rs -> {
                    Object value = rs.getObject(index);
                    return value == null ? null : normalise(value);
                }),
                new Probe("wasNull", rs -> {
                    rs.getObject(index);
                    return String.valueOf(rs.wasNull());
                }));

        for (Probe probe : probes) {
            String a = call(mine, index, probe.read());
            String b = call(theirs, index, probe.read());
            if (!equal(a, b) && !isAllowed(column.name(), probe.what())) {
                report(new Finding(column.name() + "[" + row + "]", probe.what(),
                        wrote, "both", a, b));
            }
        }
    }

    private void compareMetaData(Column column, int index, ResultSetMetaData mine,
            ResultSetMetaData theirs, String wrote) throws SQLException {
        record Probe(String what, Meta read) { }
        List<Probe> probes = List.of(
                new Probe("columnType", m -> String.valueOf(m.getColumnType(index))),
                new Probe("columnTypeName", m -> m.getColumnTypeName(index)),
                new Probe("precision", m -> String.valueOf(m.getPrecision(index))),
                new Probe("scale", m -> String.valueOf(m.getScale(index))),
                new Probe("isNullable", m -> String.valueOf(m.isNullable(index))),
                new Probe("columnClassName", m -> m.getColumnClassName(index)));

        for (Probe probe : probes) {
            String a = meta(mine, probe.read());
            String b = meta(theirs, probe.read());
            if (!equal(a, b) && !isAllowed(column.name(), probe.what())) {
                report(new Finding(column.name(), probe.what(), wrote, "both", a, b));
            }
        }
    }

    /** Each distinct disagreement once, however many rows produced it. */
    private void report(Finding finding) {
        if (reported.add(finding.column() + "|" + finding.what() + "|"
                + finding.seclume() + "|" + finding.vendor())) {
            findings.add(finding);
        }
    }

    private boolean isAllowed(String column, String what) {
        return allowed.contains(what) || allowed.contains(column + "." + what);
    }

    /**
     * Whether two answers count as the same.
     *
     * <p>Only exact equality, with one exception that is not a tolerance but a
     * normalisation: {@code BigDecimal} compares by value in {@code compareTo}
     * and by value <i>and scale</i> in {@code equals}, and the scale is
     * compared separately as metadata. Everything else is compared as the
     * string the driver produced, because that is what an application sees.
     */
    private static boolean equal(String a, String b) {
        return a == null ? b == null : a.equals(b);
    }

    /**
     * Makes two drivers' objects comparable without hiding a difference.
     *
     * <p>Drivers return their own wrappers - {@code PGobject},
     * {@code oracle.sql.TIMESTAMP} - for the same value. Comparing
     * {@code getClass()} would report a difference on every row and say
     * nothing; comparing {@code toString()} of the underlying value reports a
     * difference exactly when the values differ. A {@code byte[]} is rendered
     * as hex rather than by identity, for the same reason.
     */
    private static String normalise(Object value) {
        if (value instanceof byte[] bytes) {
            StringBuilder hex = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                hex.append(Character.forDigit((b >> 4) & 0xf, 16));
                hex.append(Character.forDigit(b & 0xf, 16));
            }
            return hex.toString();
        }
        if (value instanceof BigDecimal number) {
            return number.toPlainString();
        }
        return String.valueOf(value);
    }

    @FunctionalInterface
    private interface Read {
        String apply(ResultSet rows) throws SQLException;
    }

    @FunctionalInterface
    private interface Meta {
        String apply(ResultSetMetaData meta) throws SQLException;
    }

    /** A getter that throws is itself an answer, and a comparable one. */
    private static String call(ResultSet rows, int index, Read read) {
        try {
            return read.apply(rows);
        } catch (SQLException | RuntimeException e) {
            return "<" + e.getClass().getSimpleName() + ": " + e.getMessage() + ">";
        }
    }

    private static String meta(ResultSetMetaData metaData, Meta read) {
        try {
            return read.apply(metaData);
        } catch (SQLException | RuntimeException e) {
            return "<" + e.getClass().getSimpleName() + ">";
        }
    }

    private static String nameOf(Connection connection) {
        return connection.getClass().getName().startsWith("space.seclume")
                ? "seclume" : "vendor";
    }

    // ------------------------------------------------------------ the table --

    private void create(List<Column> columns) throws SQLException {
        drop();
        StringBuilder ddl = new StringBuilder("create table ").append(table).append(" (");
        for (int i = 0; i < columns.size(); i++) {
            if (i > 0) {
                ddl.append(", ");
            }
            ddl.append(columns.get(i).name()).append(' ').append(columns.get(i).ddl());
        }
        ddl.append(')');
        try (Statement statement = seclume.createStatement()) {
            statement.execute(ddl.toString());
        }
    }

    private void insert(Connection connection, List<Column> columns, int row)
            throws SQLException {
        String names = String.join(", ", columns.stream().map(Column::name).toList());
        String marks = String.join(", ", columns.stream().map(c -> "?").toList());
        try (PreparedStatement insert = connection.prepareStatement(
                "insert into " + table + " (" + names + ") values (" + marks + ")")) {
            for (int i = 0; i < columns.size(); i++) {
                List<Object> values = columns.get(i).values();
                Object value = row < values.size() ? values.get(row) : null;
                if (value != null) {
                    insert.setObject(i + 1, value);
                } else {
                    insert.setNull(i + 1, nullTypeOf(values));
                }
            }
            insert.executeUpdate();
        }
    }

    /**
     * Which type a null is bound as.
     *
     * <p>{@code setObject(i, null)} says nothing about the type, so the
     * driver has to invent one - and against a typed column the invention can
     * be refused. Both seclume and mssql-jdbc answer "Implicit conversion
     * from data type nvarchar to varbinary is not allowed" for a null bound
     * into a {@code varbinary}, which is agreement rather than a fault (see
     * {@code NullBindProbe}) but stops the run either way.
     *
     * <p>So the type is taken from the column's own values: whatever class
     * the non-null ones have says what a null in that column means. A column
     * that is null all the way down falls back to {@code setObject}, because
     * there is nothing to derive from and nothing being tested there either.
     */
    private static int nullTypeOf(List<Object> values) {
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            return switch (value) {
                case byte[] ignored -> java.sql.Types.VARBINARY;
                case String ignored -> java.sql.Types.VARCHAR;
                case Integer ignored -> java.sql.Types.INTEGER;
                case Long ignored -> java.sql.Types.BIGINT;
                case Short ignored -> java.sql.Types.SMALLINT;
                case Byte ignored -> java.sql.Types.TINYINT;
                case Double ignored -> java.sql.Types.DOUBLE;
                case Float ignored -> java.sql.Types.REAL;
                case BigDecimal ignored -> java.sql.Types.DECIMAL;
                case Boolean ignored -> java.sql.Types.BOOLEAN;
                case java.sql.Date ignored -> java.sql.Types.DATE;
                case java.sql.Timestamp ignored -> java.sql.Types.TIMESTAMP;
                case java.sql.Time ignored -> java.sql.Types.TIME;
                default -> java.sql.Types.OTHER;
            };
        }
        return java.sql.Types.NULL;
    }

    private void truncate() throws SQLException {
        try (Statement statement = seclume.createStatement()) {
            statement.execute("delete from " + table);
        }
    }

    private void drop() {
        try (Statement statement = seclume.createStatement()) {
            statement.execute("drop table " + table);
        } catch (SQLException notThere) {
            // First run, or a previous one cleaned up after itself.
        }
    }
}
