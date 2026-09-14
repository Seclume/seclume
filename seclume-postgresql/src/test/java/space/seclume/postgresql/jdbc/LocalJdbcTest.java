package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigDecimal;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
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
                "no .local-pg-password - skipping the tests against a real server");
        Assumptions.assumeTrue(reachable(), "no PostgreSQL on 127.0.0.1:5432");
        url = "jdbc:seclume:postgresql://127.0.0.1:5432/" + DATABASE
                + "?user=" + USER + "&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(url);
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
            assertEquals(List.of("id integer NO", "name character varying(40) NO",
                    "amount numeric(10,2) YES"), columns);

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
            assertThrows(java.sql.SQLFeatureNotSupportedException.class,
                    () -> connection.prepareCall("{ call whatever() }"));
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
        String withDeadHead = url.replace("//127.0.0.1:5432/", "//127.0.0.1:1,127.0.0.1:5432/");
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
        String allDead = url.replace("//127.0.0.1:5432/", "//127.0.0.1:1,127.0.0.1:2/");
        SQLException thrown = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(allDead));
        assertTrue(thrown.getMessage().contains("127.0.0.1:1")
                && thrown.getMessage().contains("127.0.0.1:2"), thrown.getMessage());
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
        for (Path candidate : List.of(Path.of(".local-pg-password"),
                Path.of("..", ".local-pg-password"))) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static boolean reachable() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", 5432), 1000);
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

}
