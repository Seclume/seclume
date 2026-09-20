package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import space.seclume.tck.TestHosts;

import java.io.IOException;
import java.math.BigDecimal;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.Pipeline;
import space.seclume.RoundTrips;

/**
 * The JDBC surface against the real server.
 *
 * <p>Nothing about the protocol is checked here any more - {@code
 * LocalPostgresTest} does that. This is about what an application sees:
 * {@code DriverManager.getConnection}, {@code PreparedStatement},
 * {@code ResultSet}, transactions, metadata.
 *
 * <p>The URL contains no password, only where to find one. That is the point.
 */
class LocalJdbcTest {

    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = locatePasswordFile();
        Assumptions.assumeTrue(password != null,
                "no " + TestHosts.postgresPasswordFile() + " - skipping the tests "
                        + "against a real server");
        Assumptions.assumeTrue(reachable(), "no PostgreSQL on "
                + TestHosts.postgres() + ":" + TestHosts.postgresPort());
        url = "jdbc:seclume:postgresql://" + TestHosts.postgres()
                + ":" + TestHosts.postgresPort() + "/" + DATABASE
                + "?user=" + USER + "&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(url);
    }

    /**
     * A reused plan keeps its own columns, even when another one ran between.
     *
     * <p>This is the test for the risk that came with not asking any more.
     * The first execution of a prepared statement gets the row description
     * from the server and keeps it; every one after it skips the
     * {@code DESCRIBE}, which is worth some five hundred bytes per execution.
     * The price is that the session's idea of „the current columns" is no
     * longer set by the server on each execution - so if it were not set from
     * the remembered description, the rows of one statement would be decoded
     * against the columns of whatever ran last on the connection.
     *
     * <p>Two statements with different shapes, run alternately, catch exactly
     * that: names, types and values all have to stay with their own statement.
     */

    @Test
    void aReusedPlanKeepsItsOwnColumnsAfterAnotherStatementRanBetween() throws Exception {
        try (Connection connection = connect();
             PreparedStatement two = connection.prepareStatement(
                     "select ?::int as alpha, 'text'::varchar as beta");
             PreparedStatement one = connection.prepareStatement(
                     "select ?::bigint as gamma")) {

            for (int round = 0; round < 3; round++) {
                two.setInt(1, 40 + round);
                try (ResultSet rows = two.executeQuery()) {
                    assertEquals(2, rows.getMetaData().getColumnCount(), "round " + round);
                    assertEquals("alpha", rows.getMetaData().getColumnLabel(1));
                    assertEquals("beta", rows.getMetaData().getColumnLabel(2));
                    assertTrue(rows.next());
                    assertEquals(40 + round, rows.getInt(1));
                    assertEquals("text", rows.getString(2));
                }

                one.setLong(1, 900 + round);
                try (ResultSet rows = one.executeQuery()) {
                    assertEquals(1, rows.getMetaData().getColumnCount(), "round " + round);
                    assertEquals("gamma", rows.getMetaData().getColumnLabel(1));
                    assertTrue(rows.next());
                    assertEquals(900 + round, rows.getLong(1));
                }
            }
        }
    }

    @Test
    void theDriverManagerFindsUsThroughTheServiceFile() throws Exception {
        assertNotNull(DriverManager.getDriver(url));
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("select current_user")) {
            assertTrue(result.next());
            assertEquals(USER, result.getString(1));
            assertFalse(result.next());
        }
    }

    /** A password in the URL is refused - with a reason, not silently. */
    @Test
    void aPasswordInTheUrlIsRefused() {
        SQLException failure = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url + "&password=whatever"));
        assertTrue(failure.getMessage().contains("not a seclume setting")
                        || failure.getCause() != null,
                "expected the refusal to explain itself, got: " + failure.getMessage());
    }

    @Test
    void preparedStatementsSendParametersAsParameters() throws Exception {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement(
                     "select ?::text as label, ?::int8 as number, ?::bool as flag")) {
            // A value that as text inside the SQL would be an injection.
            statement.setString(1, "'; drop table x; --");
            statement.setLong(2, 4711);
            statement.setBoolean(3, true);
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next());
                assertEquals("'; drop table x; --", result.getString("label"));
                assertEquals(4711L, result.getLong(2));
                assertTrue(result.getBoolean("flag"));
            }
        }
    }

    /**
     * Nulls and empty values scattered through a row, over several rows.
     *
     * <p>This guards a shortcut: a row is copied out of the receive buffer in
     * <b>one</b> piece rather than cell by cell, because the cells lie next to
     * each other with only their length prefixes in between. Every offset is
     * then computed from the start of that span - and a null in the first
     * column, in the middle, or at the end each shift that arithmetic
     * differently. Get one of them wrong and the values come out plausible but
     * moved by four bytes.
     */
    @Test
    void readsNullsAtEveryPositionOfARow() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("""
                     select null::text as a, 'one' as b, '' as c, 2 as d
                     union all
                     select 'three', null, 'four', 5
                     union all
                     select null, null, null, null
                     union all
                     select 'six', 'seven', '', 8
                     order by d nulls last
                     """)) {
            assertTrue(rows.next());
            assertNull(rows.getString("a"));
            assertEquals("one", rows.getString("b"));
            assertEquals("", rows.getString("c"));
            assertEquals(2, rows.getInt("d"));

            assertTrue(rows.next());
            assertEquals("three", rows.getString("a"));
            assertNull(rows.getString("b"));
            assertEquals("four", rows.getString("c"));
            assertEquals(5, rows.getInt("d"));

            assertTrue(rows.next());
            assertEquals("six", rows.getString("a"));
            assertEquals("seven", rows.getString("b"));
            assertEquals("", rows.getString("c"));
            assertEquals(8, rows.getInt("d"));

            assertTrue(rows.next(), "the row that is null in every column");
            assertNull(rows.getString("a"));
            assertNull(rows.getString("b"));
            assertNull(rows.getString("c"));
            assertEquals(0, rows.getInt("d"));
            assertTrue(rows.wasNull());

            assertFalse(rows.next());
        }
    }

    @Test
    void readsTheTypesAnApplicationActuallyUses() throws Exception {
        UUID id = UUID.randomUUID();
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement("""
                     select ?::uuid as id, ?::numeric as amount, ?::bytea as raw,
                            ?::timestamp as at, null::text as nothing
                     """)) {
            statement.setObject(1, id);
            statement.setBigDecimal(2, new BigDecimal("12345.6789"));
            statement.setBytes(3, new byte[] {0, 1, (byte) 0xff, 'z'});
            statement.setTimestamp(4, java.sql.Timestamp.valueOf("2026-09-06 12:34:56"));
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next());
                assertEquals(id, result.getObject("id"));
                assertEquals(new BigDecimal("12345.6789"), result.getBigDecimal("amount"));
                assertArrayEqualsBytes(new byte[] {0, 1, (byte) 0xff, 'z'}, result.getBytes("raw"));
                assertEquals("2026-09-06 12:34:56.0", result.getTimestamp("at").toString());
                assertEquals(null, result.getString("nothing"));
                assertTrue(result.wasNull());
            }
        }
    }

    private static void assertArrayEqualsBytes(byte[] expected, byte[] actual) {
        assertEquals(java.util.Arrays.toString(expected), java.util.Arrays.toString(actual));
    }

    /**
     * What the common shapes cost, counted rather than timed.
     *
     * <p>These numbers are the point of the whole exercise: they do not depend
     * on the network, the machine or the time of day. A change that adds a
     * round trip fails here, on a laptop, in a second - instead of showing up
     * as a vague slowdown in production six weeks later.
     *
     * <p>What the numbers mean:
     *
     * <ul>
     *   <li><b>A transaction with one statement</b> - the shape of most
     *       {@code @Transactional} methods - needs <b>two</b>: the statement,
     *       and the commit. The {@code BEGIN}, the isolation level and
     *       read-only ride along with the statement.</li>
     *   <li><b>The first use of a prepared statement</b> needs <b>one</b>:
     *       parse, bind and execute travel together.</li>
     *   <li><b>Closing a statement</b> needs <b>none</b>: the
     *       {@code deallocate} rides along with whatever comes next.</li>
     * </ul>
     */
    @Test
    void countsTheRoundTripsOfTheCommonShapes() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists zl_trips");
                statement.execute("create table zl_trips (n int, t text)");
                statement.execute("insert into zl_trips values (1, 'x')");
            }

            long before = RoundTrips.of(connection);
            try (PreparedStatement query = connection.prepareStatement(
                    "select t from zl_trips where n = ?")) {
                query.setInt(1, 1);
                try (ResultSet found = query.executeQuery()) {
                    assertTrue(found.next());
                }
            }
            assertEquals(1, RoundTrips.of(connection) - before,
                    "prepare, execute and close together are one round trip");

            before = RoundTrips.of(connection);
            connection.setAutoCommit(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
            connection.setReadOnly(true);
            try (PreparedStatement query = connection.prepareStatement(
                    "select t from zl_trips where n = ?")) {
                query.setInt(1, 1);
                try (ResultSet found = query.executeQuery()) {
                    assertTrue(found.next());
                }
            }
            connection.commit();
            connection.setReadOnly(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            connection.setAutoCommit(true);
            assertEquals(2, RoundTrips.of(connection) - before,
                    "a read-only transaction with one query costs the statement "
                    + "and the commit, nothing else");

            before = RoundTrips.of(connection);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_trips values (?, ?)")) {
                for (int i = 0; i < 100; i++) {
                    insert.setInt(1, i);
                    insert.setString(2, "row-" + i);
                    insert.addBatch();
                }
                insert.executeBatch();
            }
            assertEquals(1, RoundTrips.of(connection) - before,
                    "a hundred rows go over in one group");

            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table zl_trips");
            }
        }
    }

    /**
     * Auto-commit has to commit - checked over a <b>second</b> connection.
     *
     * <p>That detail is the whole test. A session sees its own uncommitted
     * writes, so a check over the same connection passes even when nothing was
     * ever committed - which is exactly how a data-losing bug hid in the
     * Oracle driver until somebody read with a second connection. Every driver
     * in this project gets the same test for that reason.
     */
    @Test
    void autoCommitCommitsAndTurningItOffHoldsBack() throws Exception {
        try (Connection writer = connect()) {
            try (Statement statement = writer.createStatement()) {
                statement.execute("drop table if exists zl_commit");
                statement.execute("create table zl_commit (n int)");
            }
            try {
                try (PreparedStatement insert = writer.prepareStatement(
                        "insert into zl_commit values (?)")) {
                    insert.setInt(1, 1);
                    insert.executeUpdate();              // auto-commit is on
                }
                assertEquals(1, rowsSeenElsewhere(), "auto-commit did not commit");

                writer.setAutoCommit(false);
                try (PreparedStatement insert = writer.prepareStatement(
                        "insert into zl_commit values (?)")) {
                    insert.setInt(1, 2);
                    insert.executeUpdate();
                }
                assertEquals(1, rowsSeenElsewhere(),
                        "a row appeared although the transaction was still open");
                writer.commit();
                assertEquals(2, rowsSeenElsewhere(), "commit did not commit");

                try (PreparedStatement insert = writer.prepareStatement(
                        "insert into zl_commit values (?)")) {
                    insert.setInt(1, 3);
                    insert.executeUpdate();
                }
                writer.rollback();
                assertEquals(2, rowsSeenElsewhere(), "rollback did not roll back");
            } finally {
                writer.setAutoCommit(true);
                try (Statement statement = writer.createStatement()) {
                    statement.execute("drop table zl_commit");
                }
            }
        }
    }

    /** How many rows a <b>different</b> connection can see. */
    private static int rowsSeenElsewhere() throws SQLException {
        try (Connection reader = connect();
             Statement statement = reader.createStatement();
             ResultSet found = statement.executeQuery("select count(*) from zl_commit")) {
            found.next();
            return found.getInt(1);
        }
    }

    @Test
    void writesReadsAndRollsBack() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists seclume_jdbc");
                statement.execute(
                        "create table seclume_jdbc (id int primary key, label text not null)");
            }
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into seclume_jdbc values (?, ?)")) {
                for (int i = 1; i <= 3; i++) {
                    insert.setInt(1, i);
                    insert.setString(2, "Zeile " + i);
                    assertEquals(1, insert.executeUpdate());
                }
            }

            connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement()) {
                assertEquals(3, statement.executeUpdate(
                        "update seclume_jdbc set label = 'weg'"));
            }
            connection.rollback();
            connection.setAutoCommit(true);

            List<String> labels = new ArrayList<>();
            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery(
                         "select label from seclume_jdbc order by id")) {
                while (result.next()) {
                    labels.add(result.getString(1));
                }
            }
            assertEquals(List.of("Zeile 1", "Zeile 2", "Zeile 3"), labels);

            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table seclume_jdbc");
            }
        }
    }

    /**
     * A result far larger than the receive buffer.
     *
     * <p>The rows are not copied out of that buffer - the result only writes
     * down where each value is and takes the buffer over at the end. That
     * makes one rule load-bearing: while a result is being collected the
     * buffer must not be moved. If it ever were - by compacting it, say - the
     * positions would still look plausible and point at the wrong bytes,
     * which is the worst kind of failure.
     *
     * <p>Five thousand rows of three columns are several times the initial
     * buffer, so the buffer has to grow while the result is being read. The
     * values are checked at both ends and in the middle, not just counted.
     */
    @Test
    void readsAResultManyTimesTheReceiveBuffer() throws Exception {
        int rows = 5000;
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "select i, repeat('x', 40) || i, i * 1.5 from generate_series(1, "
                     + rows + ") i")) {
            int seen = 0;
            while (result.next()) {
                seen++;
                assertEquals(seen, result.getInt(1));
                assertEquals("x".repeat(40) + seen, result.getString(2));
                assertEquals(seen * 1.5, result.getDouble(3), 0.0);
            }
            assertEquals(rows, seen);
        }
    }

    /**
     * A batch that is larger than one pipeline group.
     *
     * <p>A batch does not go out row by row - the messages are sent back to
     * back and only the group is closed with a {@code Sync}. That makes the
     * group boundary a place where a driver can lose count: the answers of one
     * group have to land on the right rows, and the next group has to start
     * where the last one ended. Six hundred rows cross that boundary at least
     * twice.
     */
    @Test
    void aBatchLargerThanOnePipelineGroupCountsEveryRow() throws Exception {
        int rows = 600;
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists seclume_pipeline");
                statement.execute("create table seclume_pipeline (n int, t text)");
            }
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into seclume_pipeline values (?, ?)")) {
                for (int i = 0; i < rows; i++) {
                    insert.setInt(1, i);
                    insert.setString(2, "row-" + i);
                    insert.addBatch();
                }
                int[] counts = insert.executeBatch();
                assertEquals(rows, counts.length, "one count per row");
                for (int count : counts) {
                    assertEquals(1, count);
                }
            }
            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery(
                         "select count(*), sum(n), min(t), max(t) from seclume_pipeline")) {
                assertTrue(result.next());
                assertEquals(rows, result.getInt(1));
                assertEquals(rows * (rows - 1) / 2, result.getInt(2));
                assertEquals("row-0", result.getString(3));
                assertEquals("row-99", result.getString(4));
            }
            // A batch that fails has to fail - and leave the session usable.
            try (PreparedStatement bad = connection.prepareStatement(
                    "insert into seclume_pipeline values (?, ?)")) {
                bad.setInt(1, 1);
                bad.setString(2, "fine");
                bad.addBatch();
                bad.setString(1, "not a number");
                bad.setString(2, "broken");
                bad.addBatch();
                assertThrows(SQLException.class, bad::executeBatch);
            }
            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("select 1")) {
                assertTrue(result.next(), "the session is unusable after a failed batch");
            }
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table seclume_pipeline");
            }
        }
    }

    @Test
    void aBatchRunsEveryRow() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists seclume_batch");
                statement.execute("create table seclume_batch (n int)");
            }
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into seclume_batch values (?)")) {
                for (int i = 0; i < 10; i++) {
                    insert.setInt(1, i);
                    insert.addBatch();
                }
                int[] counts = insert.executeBatch();
                assertEquals(10, counts.length);
                for (int count : counts) {
                    assertEquals(1, count);
                }
            }
            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery(
                         "select count(*), sum(n) from seclume_batch")) {
                assertTrue(result.next());
                assertEquals(10, result.getInt(1));
                assertEquals(45, result.getInt(2));
            }
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table seclume_batch");
            }
        }
    }

    @Test
    void metaDataDescribesColumnsAndTables() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists seclume_meta");
                statement.execute("create table seclume_meta ("
                        + "id int primary key, name varchar(40) not null, amount numeric(10,2))");
            }
            DatabaseMetaData meta = connection.getMetaData();
            assertEquals("PostgreSQL", meta.getDatabaseProductName());
            assertEquals("seclume", meta.getDriverName());

            List<String> tables = new ArrayList<>();
            try (ResultSet result = meta.getTables(null, "public", "seclume_meta", null)) {
                while (result.next()) {
                    tables.add(result.getString("TABLE_NAME") + ":" + result.getString("TABLE_TYPE"));
                }
            }
            assertEquals(List.of("seclume_meta:TABLE"), tables);

            List<String> columns = new ArrayList<>();
            try (ResultSet result = meta.getColumns(null, "public", "seclume_meta", null)) {
                while (result.next()) {
                    columns.add(result.getString("COLUMN_NAME") + " "
                            + result.getString("TYPE_NAME") + " "
                            + result.getString("IS_NULLABLE"));
                }
            }
            // The internal type names, which is what pgjdbc and every other
            // driver answer here - not the SQL spelling with the length
            // attached. TYPE_NAME is a type name, not a column declaration,
            // and a dialect that matches on it does not recognise
            // "character varying(40)". This test used to hold the old
            // answers; the differential run against pgjdbc is what showed
            // they were seclume's alone. See seclume-diff.
            assertEquals(List.of("id int4 NO", "name varchar NO",
                    "amount numeric YES"), columns);

            try (ResultSet result = meta.getPrimaryKeys(null, "public", "seclume_meta")) {
                assertTrue(result.next());
                assertEquals("id", result.getString("COLUMN_NAME"));
                assertFalse(result.next());
            }

            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("select * from seclume_meta")) {
                ResultSetMetaData rowMeta = result.getMetaData();
                assertEquals(3, rowMeta.getColumnCount());
                assertEquals("id", rowMeta.getColumnLabel(1));
                assertEquals(Types.INTEGER, rowMeta.getColumnType(1));
                assertEquals("varchar", rowMeta.getColumnTypeName(2));
                assertEquals(40, rowMeta.getPrecision(2));
                assertEquals(Types.NUMERIC, rowMeta.getColumnType(3));
                assertEquals(10, rowMeta.getPrecision(3));
                assertEquals(2, rowMeta.getScale(3));
                assertEquals(ResultSetMetaData.columnNullableUnknown, rowMeta.isNullable(1));
            }

            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table seclume_meta");
            }
        }
    }

    /** An error from the server arrives as a SQLException with a SQLState. */
    @Test
    void serverErrorsReachTheApplication() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            SQLException failure = assertThrows(SQLException.class,
                    () -> statement.executeQuery("select * from nope_not_here"));
            assertEquals("42P01", failure.getSQLState());
            // The connection survives the error.
            assertTrue(connection.isValid(1));
        }
    }

    /**
     * A broken prepared statement reports what is wrong with it, once.
     *
     * <p>The Parse is deferred and travels with the first Bind and Execute, in
     * one block closed by a single Sync. That is what makes this worth a test:
     * the server rejects the Parse and then skips everything up to the Sync,
     * so the Bind against a statement that was never created produces nothing
     * of its own. What comes back is the syntax error, not a confusing "prepared
     * statement does not exist" after it - and the connection stays usable.
     */
    @Test
    void aBrokenPreparedStatementReportsItsOwnError() throws Exception {
        try (Connection connection = connect()) {
            try (PreparedStatement statement =
                         connection.prepareStatement("select * from nope_not_here where x = ?")) {
                statement.setInt(1, 1);
                SQLException failure = assertThrows(SQLException.class, statement::executeQuery);
                assertEquals("42P01", failure.getSQLState(),
                        "the table error, not a follow-up about the statement: "
                                + failure.getMessage());
            }
            assertTrue(connection.isValid(1), "the connection did not survive the error");
            // And it still works afterwards - the session is not left mid-block.
            try (PreparedStatement statement = connection.prepareStatement("select 7");
                 ResultSet result = statement.executeQuery()) {
                assertTrue(result.next());
                assertEquals(7, result.getInt(1));
            }
        }
    }

    // ---- the plan cache --------------------------------------------------

    /**
     * The server's own view of what this session has prepared.
     *
     * <p>A throwaway statement runs first on purpose: releasing a plan rides
     * along with the next statement, so asking without it would see plans that
     * are already on their way out.
     */
    private static List<String> plansOnTheServer(Connection connection) throws SQLException {
        try (Statement flush = connection.createStatement()) {
            flush.execute("select 1");
        }
        List<String> names = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select name from pg_prepared_statements order by name")) {
            while (rows.next()) {
                names.add(rows.getString(1));
            }
        }
        return names;
    }

    /**
     * Closing a statement gives its plan back instead of throwing it away.
     *
     * <p>Without this every {@code prepareStatement} is a fresh plan on the
     * server - parsed, planned, used once, deallocated - and the shape that
     * pays for it is the commonest there is: a method that prepares, runs and
     * closes, called over and over. Measured at 33.7 microseconds against
     * pgjdbc's 22.8 on a loopback connection, and level at 22.0 with the cache.
     */
    @Test
    void aClosedPlanIsReusedForTheSameSql() throws Exception {
        try (Connection connection = connect()) {
            String first = runAndClose(connection, "select 41 + 1");
            assertEquals(List.of(first), plansOnTheServer(connection),
                    "the plan should still be there, and be the only one");

            String second = runAndClose(connection, "select 41 + 1");
            assertEquals(first, second, "the same SQL should have got the same plan back");
            assertEquals(List.of(first), plansOnTheServer(connection),
                    "a reused plan must not leave a second one behind");
        }
    }

    /** Runs a statement once and closes it; answers which plan it used. */
    private static String runAndClose(Connection connection, String sql) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            try (ResultSet rows = statement.executeQuery()) {
                assertTrue(rows.next());
                assertEquals(42, rows.getInt(1));
            }
            // The name is not public API; the server knows it, which is the
            // point of asking the server rather than the driver.
            try (Statement lookup = connection.createStatement();
                 ResultSet rows = lookup.executeQuery(
                         "select name from pg_prepared_statements order by prepare_time desc "
                                 + "limit 1")) {
                assertTrue(rows.next(), "the server should know the plan while it is open");
                return rows.getString(1);
            }
        }
    }

    /**
     * Two statements on the same SQL at once do not share a plan.
     *
     * <p>They would share the unnamed portal with it, and then one of them
     * would be reading the other's rows. This is why a plan is cached when the
     * statement <b>closes</b> and not when it is created.
     */
    @Test
    void twoOpenStatementsOnTheSameSqlStayApart() throws Exception {
        try (Connection connection = connect();
             PreparedStatement one = connection.prepareStatement("select ?::int");
             PreparedStatement two = connection.prepareStatement("select ?::int")) {
            one.setInt(1, 1);
            two.setInt(1, 2);
            for (int i = 0; i < 3; i++) {
                try (ResultSet rows = one.executeQuery()) {
                    assertTrue(rows.next());
                    assertEquals(1, rows.getInt(1), "the first statement read the wrong rows");
                }
                try (ResultSet rows = two.executeQuery()) {
                    assertTrue(rows.next());
                    assertEquals(2, rows.getInt(1), "the second statement read the wrong rows");
                }
            }
            assertEquals(2, plansOnTheServer(connection).size(),
                    "two open statements need two plans");
        }
    }

    /** With the cache off, a closed plan is released as it was before. */
    @Test
    void theCacheCanBeSwitchedOff() throws Exception {
        try (Connection connection = DriverManager.getConnection(url + "&statementCacheSize=0")) {
            runAndClose(connection, "select 41 + 1");
            assertEquals(List.of(), plansOnTheServer(connection),
                    "nothing should be kept when the cache is off");
        }
    }

    /** A full cache drops the plan that has gone longest unused. */
    @Test
    void theOldestPlanIsReleasedWhenTheCacheIsFull() throws Exception {
        try (Connection connection = DriverManager.getConnection(url + "&statementCacheSize=1")) {
            runAndClose(connection, "select 41 + 1");
            runAndClose(connection, "select 40 + 2");
            assertEquals(1, plansOnTheServer(connection).size(),
                    "a cache of one should hold one plan, not two");
        }
    }

    /**
     * A plan whose Parse failed is not kept.
     *
     * <p>It does not exist on the server, so handing it to the next caller
     * would be a Bind against nothing - which is the same class of confusion
     * the deallocate defect produced, arriving from the other side.
     */
    @Test
    void aPlanThatNeverRanIsNotCached() throws Exception {
        try (Connection connection = connect()) {
            try (PreparedStatement broken =
                         connection.prepareStatement("select * from nope_not_here")) {
                assertThrows(SQLException.class, broken::executeQuery);
            }
            assertEquals(List.of(), plansOnTheServer(connection));
            // And the same SQL afterwards fails on its own merits, not with a
            // complaint about a statement that does not exist.
            try (PreparedStatement again =
                         connection.prepareStatement("select * from nope_not_here")) {
                SQLException failure = assertThrows(SQLException.class, again::executeQuery);
                assertEquals("42P01", failure.getSQLState(), failure.getMessage());
            }
        }
    }

    /** What does not work says so - instead of quietly returning something wrong. */
    @Test
    void unsupportedThingsSayNo() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            assertThrows(java.sql.SQLFeatureNotSupportedException.class,
                    () -> statement.setQueryTimeout(5));
            // getGeneratedKeys works now; what it answers when nobody asked
            // for keys is an empty result set, as JDBC prescribes - not an
            // exception.
            try (ResultSet none = statement.getGeneratedKeys()) {
                assertFalse(none.next(), "there were no keys to hand out");
            }
            assertThrows(java.sql.SQLFeatureNotSupportedException.class,
                    () -> connection.prepareStatement("insert into nothing values (1)",
                            new int[] {1}));
            try (ResultSet result = statement.executeQuery("select 1")) {
                assertTrue(result.next());
                assertThrows(java.sql.SQLFeatureNotSupportedException.class, result::previous);
            }
        }
    }

    /**
     * A dead server first in the list, the real one behind it.
     *
     * <p>This is failover at the moment of connecting - the case that covers a
     * rolling update. Port 1 is refused straight away, so the test does not
     * wait for a timeout to prove the point.
     */
    @Test
    void connectsToTheSecondServerWhenTheFirstIsDead() throws Exception {
        String alive = TestHosts.postgres() + ":" + TestHosts.postgresPort();
        String withDeadHead = url.replace("//" + alive + "/",
                "//" + TestHosts.postgres() + ":1," + alive + "/");
        try (Connection connection = DriverManager.getConnection(withDeadHead);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select 1")) {
            assertTrue(rows.next());
            assertEquals(1, rows.getInt(1));
        }
    }

    /** And when none of them answers, the message says what was tried. */
    @Test
    void namesEveryServerItTriedWhenNoneAnswers() {
        String dead = TestHosts.postgres();
        String allDead = url.replace(
                "//" + dead + ":" + TestHosts.postgresPort() + "/",
                "//" + dead + ":1," + dead + ":2/");
        SQLException thrown = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(allDead));
        assertTrue(thrown.getMessage().contains(dead + ":1")
                && thrown.getMessage().contains(dead + ":2"), thrown.getMessage());
    }

    /**
     * A result that runs away ends in an error that names the query.
     *
     * <p>The alternative, in every other driver, is an
     * {@code OutOfMemoryError} whose stack trace names an allocation and not
     * the statement that caused it.
     */
    @Test
    void aResultLargerThanTheLimitIsRefusedWithTheStatementInTheMessage() throws Exception {
        String bounded = url + "&maxResultBytes=4096";
        try (Connection connection = DriverManager.getConnection(bounded);
             Statement statement = connection.createStatement()) {
            SQLException thrown = assertThrows(SQLException.class,
                    () -> statement.executeQuery(
                            "select repeat('x', 200) from generate_series(1, 1000)"));
            assertEquals("54001", thrown.getSQLState());
            assertTrue(thrown.getMessage().contains("generate_series"), thrown.getMessage());
            assertTrue(thrown.getMessage().contains("4096"), thrown.getMessage());

            // And the connection is still usable: the rest of the answer was
            // read to the end, so the session is in step with the server.
            try (ResultSet rows = statement.executeQuery("select 42")) {
                assertTrue(rows.next());
                assertEquals(42, rows.getInt(1));
            }
        }
    }

    /** And a result inside the limit is not touched by any of it. */
    @Test
    void aResultInsideTheLimitGoesThrough() throws Exception {
        String bounded = url + "&maxResultBytes=4096&maxResultRows=100";
        try (Connection connection = DriverManager.getConnection(bounded);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select n from generate_series(1, 50) as n")) {
            int seen = 0;
            while (rows.next()) {
                seen++;
            }
            assertEquals(50, seen);
        }
    }

    /** The row bound says what it is, unlike setMaxRows which just cuts. */
    @Test
    void tooManyRowsAreRefusedRatherThanSilentlyCutOff() throws Exception {
        String bounded = url + "&maxResultRows=10";
        try (Connection connection = DriverManager.getConnection(bounded);
             Statement statement = connection.createStatement()) {
            SQLException thrown = assertThrows(SQLException.class,
                    () -> statement.executeQuery("select n from generate_series(1, 100) as n"));
            assertEquals("54001", thrown.getSQLState());
            assertTrue(thrown.getMessage().contains("maxResultRows"), thrown.getMessage());
        }
    }

    /**
     * Five writes, one round trip.
     *
     * <p>The number is the point, and it is counted rather than timed: five
     * statements sent one by one cost five round trips, and on a network with
     * any latency at all that is the whole of the time. See
     * {@link space.seclume.Pipeline}.
     */
    @Test
    void aPipelineBlockCostsOneRoundTripForTheWholeUnitOfWork() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("create temporary table zl_pipe (n int)");
            }
            connection.setAutoCommit(false);
            try (PreparedStatement insert =
                         connection.prepareStatement("insert into zl_pipe values (?)")) {
                // Once, so that the plan is on the server and the measurement
                // is about the sending and not about the parse.
                insert.setInt(1, 0);
                insert.executeUpdate();
                connection.commit();

                long before = RoundTrips.of(connection);
                try (Pipeline unit = Pipeline.open(connection)) {
                    for (int i = 1; i <= 5; i++) {
                        insert.setInt(1, i);
                        assertEquals(Statement.SUCCESS_NO_INFO, insert.executeUpdate(),
                                "a buffered write must not invent a count");
                    }
                    assertEquals(before, RoundTrips.of(connection),
                            "nothing may have gone out yet");
                    assertEquals(0, unit.counts().length, "no counts before the block ends");
                }
                long spent = RoundTrips.of(connection) - before;
                assertEquals(1, spent, "five writes have to cost one round trip");
                connection.commit();
            }
            connection.setAutoCommit(true);
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select count(*) from zl_pipe")) {
                assertTrue(rows.next());
                assertEquals(6, rows.getInt(1));
            }
        }
    }

    /** And the counts arrive afterwards, in the order they were written. */
    @Test
    void theBlockReportsWhatEachStatementDid() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("create temporary table zl_pipe_counts (n int)");
            }
            connection.setAutoCommit(false);
            try (PreparedStatement insert =
                         connection.prepareStatement("insert into zl_pipe_counts values (?)")) {
                Pipeline unit = Pipeline.open(connection);
                for (int i = 1; i <= 3; i++) {
                    insert.setInt(1, i);
                    insert.executeUpdate();
                }
                unit.close();
                assertArrayEquals(new long[] {1, 1, 1}, unit.counts());
            }
            connection.commit();
        }
    }

    /**
     * When one of them fails, the message says which - and that the ones
     * behind it did not run, because the server skips the rest of the group.
     */
    @Test
    void aFailureInTheBlockNamesTheStatementAndWhatWasSkipped() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("create temporary table zl_pipe_fail (n int primary key)");
            }
            connection.setAutoCommit(false);
            try (PreparedStatement insert =
                         connection.prepareStatement("insert into zl_pipe_fail values (?)")) {
                SQLException thrown = assertThrows(SQLException.class, () -> {
                    Pipeline unit = Pipeline.open(connection);
                    int[] values = {1, 2, 2, 3, 4};       // the third one collides
                    for (int value : values) {
                        insert.setInt(1, value);
                        insert.executeUpdate();
                    }
                    unit.close();
                });
                assertTrue(thrown.getMessage().contains("statement 3"), thrown.getMessage());
                assertTrue(thrown.getMessage().contains("skipped"), thrown.getMessage());
                assertTrue(thrown.getMessage().contains("zl_pipe_fail"), thrown.getMessage());
            }
            connection.rollback();
        }
    }

    /** Without a transaction the block is refused, and the reason is given. */
    @Test
    void aBlockInAutoCommitIsRefused() throws Exception {
        try (Connection connection = connect()) {
            SQLException thrown = assertThrows(SQLException.class,
                    () -> Pipeline.open(connection));
            assertTrue(thrown.getMessage().contains("setAutoCommit(false)"),
                    thrown.getMessage());
        }
    }

    /**
     * A big result is read in blocks, not all at once.
     *
     * <p>Counted rather than guessed: with a fetch size of 100 a result of
     * 1000 rows costs eleven round trips and every row arrives exactly once,
     * in order. Without block cursors the whole result would sit in memory,
     * which is the first thing that hurts about a large query.
     *
     * <p><b>Eleven, not ten</b>, and that is the protocol and not a bug: the
     * tenth block comes back full, so the server has said nothing about the
     * end yet. Only the eleventh {@code Execute} answers with no rows and a
     * {@code CommandComplete}. A result whose size is not a multiple of the
     * block size costs one round trip less, because the short block already
     * says it was the last.
     */
    @Test
    void aFetchSizeReadsTheResultInBlocks() throws Exception {
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);      // the portal lives in the transaction
            try (PreparedStatement query = connection.prepareStatement(
                    "select n from generate_series(1, 1000) as n")) {
                query.setFetchSize(100);
                long before = RoundTrips.of(connection);
                long sum = 0;
                int seen = 0;
                try (ResultSet rows = query.executeQuery()) {
                    while (rows.next()) {
                        seen++;
                        assertEquals(seen, rows.getInt(1), "the rows arrived out of order");
                        sum += rows.getInt(1);
                    }
                }
                long spent = RoundTrips.of(connection) - before;
                assertEquals(1000, seen, "rows lost");
                assertEquals(500500L, sum, "the values changed");
                assertEquals(11, spent, "ten blocks of a hundred rows, plus the one "
                        + "that finds out there are no more");
            }
            connection.commit();
        }
    }

    /** A result that does not fill the last block saves that extra call. */
    @Test
    void aResultThatEndsShortCostsOneRoundTripLess() throws Exception {
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            try (PreparedStatement query = connection.prepareStatement(
                    "select n from generate_series(1, 950) as n")) {
                query.setFetchSize(100);
                long before = RoundTrips.of(connection);
                int seen = 0;
                try (ResultSet rows = query.executeQuery()) {
                    while (rows.next()) {
                        seen++;
                    }
                }
                assertEquals(950, seen);
                assertEquals(10, RoundTrips.of(connection) - before,
                        "nine full blocks and one short one that says it is the last");
            }
            connection.commit();
        }
    }

    /** Without a fetch size nothing changes: one round trip, everything. */
    @Test
    void withoutAFetchSizeTheWholeResultComesAtOnce() throws Exception {
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            try (PreparedStatement query = connection.prepareStatement(
                    "select n from generate_series(1, 1000) as n")) {
                long before = RoundTrips.of(connection);
                int seen = 0;
                try (ResultSet rows = query.executeQuery()) {
                    while (rows.next()) {
                        seen++;
                    }
                }
                assertEquals(1000, seen);
                assertEquals(1, RoundTrips.of(connection) - before);
            }
            connection.commit();
        }
    }

    /**
     * A result set given back early lets go of the portal.
     *
     * <p>Otherwise the rest of the rows would sit in the server until the
     * transaction ends, and the next statement would quietly throw them away.
     */
    @Test
    void aHalfReadResultSetCanBeClosedAndTheConnectionKeepsWorking() throws Exception {
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            try (PreparedStatement query = connection.prepareStatement(
                    "select n from generate_series(1, 1000) as n")) {
                query.setFetchSize(10);
                try (ResultSet rows = query.executeQuery()) {
                    assertTrue(rows.next());
                    assertEquals(1, rows.getInt(1));
                }                                  // closed after one row
            }
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select 42")) {
                assertTrue(rows.next());
                assertEquals(42, rows.getInt(1));
            }
            connection.commit();
        }
    }

    /**
     * Generated keys - the thing every {@code @GeneratedValue} entity needs.
     *
     * <p>PostgreSQL has no separate channel for them and needs none:
     * {@code returning} makes the insert answer with the rows it wrote. So the
     * driver rewrites the statement, which is also why the answer is honest -
     * what comes back is what the server stored.
     */
    @Test
    void generatedKeysComeBackFromAnInsert() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("create temporary table zl_keys ("
                        + "id bigint generated by default as identity primary key, "
                        + "name text not null)");
            }
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_keys (name) values (?)",
                    Statement.RETURN_GENERATED_KEYS)) {
                insert.setString(1, "first");
                assertEquals(1, insert.executeUpdate());
                try (ResultSet keys = insert.getGeneratedKeys()) {
                    assertTrue(keys.next(), "no key came back");
                    assertTrue(keys.getLong("id") > 0);
                }
            }
            // And by name, which is what Hibernate asks for.
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_keys (name) values (?)", new String[] {"id"})) {
                insert.setString(1, "second");
                insert.executeUpdate();
                try (ResultSet keys = insert.getGeneratedKeys()) {
                    assertTrue(keys.next());
                    assertEquals(1, keys.getMetaData().getColumnCount(),
                            "only the named column belongs in the keys");
                }
            }
        }
    }

    /** A statement that already returns something is left alone. */
    @Test
    void aStatementThatAlreadyReturnsIsNotRewrittenTwice() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("create temporary table zl_keys2 ("
                        + "id bigint generated by default as identity primary key, n int)");
            }
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_keys2 (n) values (?) returning id",
                    Statement.RETURN_GENERATED_KEYS)) {
                insert.setInt(1, 7);
                insert.executeUpdate();
                try (ResultSet keys = insert.getGeneratedKeys()) {
                    assertTrue(keys.next());
                    assertEquals(1, keys.getMetaData().getColumnCount());
                }
            }
        }
    }

    private static Path locatePasswordFile() {
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static boolean reachable() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    TestHosts.postgres(), TestHosts.postgresPort()), 1000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
    /**
     * The type list, against the real server.
     *
     * <p>These queries are only ever proven by running them: a text block that
     * compiles says nothing about whether the server accepts it. And Flyway
     * and Liquibase call exactly this method.
     */
    @Test
    void theTypeListNamesRealJdbcTypes() throws Exception {
        try (Connection connection = connect();
             ResultSet types = connection.getMetaData().getTypeInfo()) {
            List<String> names = new ArrayList<>();
            int previous = Integer.MIN_VALUE;
            while (types.next()) {
                names.add(types.getString("TYPE_NAME"));
                int type = types.getInt("DATA_TYPE");
                assertTrue(type != 0, "the type list still reports 0 for "
                        + types.getString("TYPE_NAME"));
                // JDBC prescribes the order, and tools rely on it.
                assertTrue(type >= previous, "the list is not ordered by DATA_TYPE");
                previous = type;
                assertEquals(10, types.getInt("NUM_PREC_RADIX"));
            }
            assertTrue(names.contains("int4"), "int4 is missing: " + names);
            assertTrue(names.contains("timestamptz"), "timestamptz is missing: " + names);
        }
    }

    /**
     * {@code getColumns} has to name the JDBC type, not a placeholder -
     * Hibernate compares the schema against it.
     */
    @Test
    void theColumnListNamesTheJdbcType() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists zl_types");
            statement.execute("""
                    create table zl_types (
                        id integer primary key,
                        name varchar(40),
                        amount numeric(10,2),
                        created timestamp,
                        flag boolean
                    )""");
            try (ResultSet columns = connection.getMetaData()
                    .getColumns(null, null, "zl_types", null)) {
                java.util.Map<String, Integer> found = new java.util.HashMap<>();
                while (columns.next()) {
                    found.put(columns.getString("COLUMN_NAME"), columns.getInt("DATA_TYPE"));
                }
                assertEquals(Types.INTEGER, found.get("id"));
                assertEquals(Types.VARCHAR, found.get("name"));
                assertEquals(Types.NUMERIC, found.get("amount"));
                assertEquals(Types.TIMESTAMP, found.get("created"));
                assertEquals(Types.BOOLEAN, found.get("flag"));
            }
            statement.execute("drop table zl_types");
        }
    }

    // ---- procedure calls --------------------------------------------------

    /**
     * A procedure with an {@code INOUT} parameter, through
     * {@code CallableStatement} - the shape {@code SimpleJdbcCall} and Spring
     * Data's {@code @Procedure} use.
     *
     * <p>PostgreSQL answers a {@code CALL} with one row holding the outputs,
     * which is the whole mechanism; what is being tested is that the escape
     * syntax reaches it and the value comes back under the right index.
     */
    @Test
    void callsAProcedureAndReadsItsOutput() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("create or replace procedure zl_double(inout n int) "
                    + "language plpgsql as $$ begin n := n * 2; end $$");
            try (CallableStatement call = connection.prepareCall("{call zl_double(?)}")) {
                call.setInt(1, 21);
                call.registerOutParameter(1, Types.INTEGER);
                call.execute();
                assertEquals(42, call.getInt(1));
                assertFalse(call.wasNull());
            }
            statement.execute("drop procedure zl_double(int)");
        }
    }

    /** Two outputs, so that the second one cannot pass by landing on the first. */
    @Test
    void callsAProcedureWithTwoOutputs() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("create or replace procedure zl_split("
                    + "in text_in text, inout head text, inout tail text) "
                    + "language plpgsql as $$ begin "
                    + "head := split_part(text_in, '-', 1); "
                    + "tail := split_part(text_in, '-', 2); end $$");
            try (CallableStatement call = connection.prepareCall("{call zl_split(?, ?, ?)}")) {
                call.setString(1, "left-right");
                call.registerOutParameter(2, Types.VARCHAR);
                call.registerOutParameter(3, Types.VARCHAR);
                call.execute();
                assertEquals("left", call.getString(2));
                assertEquals("right", call.getString(3));
            }
            statement.execute("drop procedure zl_split(text, text, text)");
        }
    }

    /**
     * A function with a return value - <code>{? = call f(?)}</code>, where the
     * caller counts the return as parameter 1 and everything else shifts.
     */
    @Test
    void callsAFunctionAndReadsItsReturnValue() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("create or replace function zl_triple(n int) returns int "
                    + "language sql as $$ select n * 3 $$");
            try (CallableStatement call = connection.prepareCall("{? = call zl_triple(?)}")) {
                call.registerOutParameter(1, Types.INTEGER);
                call.setInt(2, 14);           // parameter 2, because 1 is the return value
                call.execute();
                assertEquals(42, call.getInt(1));
            }
            statement.execute("drop function zl_triple(int)");
        }
    }

    /** A NULL output is a NULL, and says so through wasNull. */
    @Test
    void anOutputThatIsNullSaysSo() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("create or replace procedure zl_nothing(inout n int) "
                    + "language plpgsql as $$ begin n := null; end $$");
            try (CallableStatement call = connection.prepareCall("{call zl_nothing(?)}")) {
                call.registerOutParameter(1, Types.INTEGER);
                call.execute();
                assertEquals(0, call.getInt(1));
                assertTrue(call.wasNull(), "an output that came back NULL has to report it");
            }
            statement.execute("drop procedure zl_nothing(int)");
        }
    }

    /**
     * Parameters addressed by the name the procedure declared.
     *
     * <p>The procedure subtracts, and the arguments are set in the wrong
     * order on purpose - {@code minus} before {@code base}. Subtraction is
     * not symmetric, so a driver that ignored the names and filled the
     * positions in the order it was called would answer 60 instead of -60.
     * The output is read by name as well, and the case is deliberately not
     * the case the catalog stores.
     */
    @Test
    void addressesParametersByName() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("create or replace procedure zl_minus("
                    + "in base int, in minus int, inout answer int) "
                    + "language plpgsql as $$ begin answer := base - minus; end $$");
            try (CallableStatement call = connection.prepareCall("{call zl_minus(?, ?, ?)}")) {
                call.setInt("minus", 100);
                call.setInt("BASE", 40);
                call.registerOutParameter("answer", Types.INTEGER);
                call.execute();
                assertEquals(-60, call.getInt("answer"));
            }
            statement.execute("drop procedure zl_minus(int, int, int)");
        }
    }

    /** A name the procedure does not declare is refused, and the message says what it does. */
    @Test
    void refusesAParameterNameThatIsNotThere() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("create or replace procedure zl_named(inout n int) "
                    + "language plpgsql as $$ begin n := n; end $$");
            try (CallableStatement call = connection.prepareCall("{call zl_named(?)}")) {
                SQLException refused = org.junit.jupiter.api.Assertions.assertThrows(
                        SQLException.class, () -> call.setInt("nope", 1));
                assertTrue(refused.getMessage().contains("nope")
                        && refused.getMessage().contains("n at 1"), refused.getMessage());
            }
            statement.execute("drop procedure zl_named(int)");
        }
    }

    /**
     * The catalog describes a procedure, which is what a call framework reads.
     *
     * <p>The {@code OUT} parameter is the point: PostgreSQL keeps the input
     * arguments in one array and all of them in another, and a driver that
     * reads the first one alone describes this procedure as having a single
     * parameter - which is how Spring would then bind it.
     */
    @Test
    void describesAProceduresParameters() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("create or replace procedure zl_described("
                    + "in n int, inout doubled int, out note text) "
                    + "language plpgsql as $$ begin doubled := n * 2; note := 'x'; end $$");
            List<String> described = new ArrayList<>();
            try (ResultSet columns = connection.getMetaData()
                    .getProcedureColumns(null, null, "zl_described", null)) {
                while (columns.next()) {
                    described.add(columns.getString("COLUMN_NAME") + " "
                            + columns.getShort("COLUMN_TYPE") + " "
                            + columns.getInt("DATA_TYPE"));
                }
            }
            assertEquals(List.of("n 1 4", "doubled 2 4", "note 4 12"), described);
            statement.execute("drop procedure zl_described(int, int, text)");
        }
    }

    /** What is not a call is refused before anything reaches the server. */
    @Test
    void refusesSqlThatIsNotACall() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            SQLException refused = org.junit.jupiter.api.Assertions.assertThrows(
                    SQLException.class, () -> connection.prepareCall("select 1"));
            assertTrue(refused.getMessage().contains("{call p(?)}"), refused.getMessage());
        }
    }
}
