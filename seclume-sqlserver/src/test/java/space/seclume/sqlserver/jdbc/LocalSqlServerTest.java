package space.seclume.sqlserver.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import space.seclume.RoundTrips;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The SQL Server driver against a <b>real</b> server.
 *
 * <p>Everything above the login was checked against synthetic token streams so
 * far. Those prove that the reader does what the writer meant - not that either
 * matches SQL Server. This test is where that gets decided: column
 * descriptions, rows, {@code MAX} values in chunks, {@code sp_executesql} with
 * typed parameters, and the catalog queries behind {@code DatabaseMetaData}.
 *
 * <p>The URL carries no password, only where to find one.
 *
 * <p>Without a reachable server the test is skipped, not failed. To start one:
 * {@code podman run -d --name seclume-mssql --env-file … -p 1433:1433
 * mcr.microsoft.com/mssql/server:2022-latest}.
 */
class LocalSqlServerTest {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);
    private static final String USER = "sa";

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mssql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
        // trustServerCertificate: the container makes its own certificate, and
        // nobody signed it. Deliberate here and named as what it is.
        url = "jdbc:seclume:sqlserver://" + HOST + ":" + PORT + "/master"
                + "?user=" + USER + "&trustServerCertificate=true&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(url);
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
                statement.execute("if object_id('zl_commit') is not null drop table zl_commit");
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

    /**
     * A session setting costs nothing when a batch statement follows it.
     *
     * <p>{@code set implicit_transactions on} on its own is a round trip in
     * which the database does nothing, and a framework sends it twice per
     * transaction. Sent in the same text as the statement that follows, it is
     * free. Only a batch can do this - see {@code TdsSession#runLater} for the
     * measured reason why a prepared statement cannot.
     */
    @Test
    void aSessionSettingRidesAlongWithTheNextBatchStatement() throws Exception {
        try (Connection connection = connect()) {
            try (Statement warmup = connection.createStatement();
                 ResultSet ignored = warmup.executeQuery("select 1")) {
                assertTrue(ignored.next());
            }
            long before = RoundTrips.of(connection);
            connection.setAutoCommit(false);
            assertEquals(before, RoundTrips.of(connection),
                    "the setting must not go out on its own");
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select 1")) {
                assertTrue(rows.next());
            }
            assertEquals(1, RoundTrips.of(connection) - before,
                    "setting and statement have to travel together");
            connection.rollback();
            connection.setAutoCommit(true);
        }
    }

    /**
     * A big result is read in blocks, not all at once.
     *
     * <p>SQL Server keeps the rows in a <b>server-side cursor</b>:
     * {@code sp_cursoropen} makes one, {@code sp_cursorfetch} brings a block,
     * {@code sp_cursorclose} gives it back. A short block says it was the last.
     *
     * <p>Two tokens had to be learned for this: a cursor result also names the
     * table its columns came from ({@code TABNAME}) and which of them make up
     * the key ({@code COLINFO}). Neither is of any use here, both are stepped
     * over - but a driver that does not know them cannot read the answer at
     * all.
     */
    @Test
    void aFetchSizeReadsTheResultInBlocks() throws Exception {
        try (Connection connection = connect()) {
            fillBlockTable(connection);
            try (PreparedStatement query = connection.prepareStatement(
                    "select n from zl_blocks order by n")) {
                query.setFetchSize(100);
                long before = RoundTrips.of(connection);
                int seen = 0;
                long sum = 0;
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
                assertTrue(spent >= 10, "a thousand rows in blocks of a hundred cannot "
                        + "cost " + spent + " round trips");
            } finally {
                dropBlockTable(connection);
            }
        }
    }

    /**
     * With bind values the fetch size is ignored - and nothing breaks.
     *
     * <p>{@code sp_cursorprepexec} refuses the parameter list this driver
     * sends ("the value of the parameter scrollopt is invalid" was solved,
     * "procedure expects parameter 'params' of type nvarchar" was not). Half a
     * cursor would be worse than none, so the statement reads the whole result
     * exactly as it did before - and says so in the documentation rather than
     * failing at the caller.
     */
    @Test
    void aFetchSizeWithBindValuesFallsBackToReadingEverything() throws Exception {
        try (Connection connection = connect()) {
            fillBlockTable(connection);
            try (PreparedStatement query = connection.prepareStatement(
                    "select n from zl_blocks where n > ? order by n")) {
                query.setInt(1, 500);
                query.setFetchSize(100);
                int seen = 0;
                try (ResultSet rows = query.executeQuery()) {
                    while (rows.next()) {
                        seen++;
                    }
                }
                assertEquals(500, seen);
            } finally {
                dropBlockTable(connection);
            }
        }
    }

    private static void fillBlockTable(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_blocks') is not null drop table zl_blocks");
            statement.execute("create table zl_blocks (n int)");
            statement.execute("with s as (select 1 as n union all select n + 1 from s "
                    + "where n < 1000) insert into zl_blocks select n from s "
                    + "option (maxrecursion 0)");
        }
    }

    private static void dropBlockTable(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_blocks') is not null drop table zl_blocks");
        }
    }

    /**
     * A batch of two hundred rows costs <b>one</b> round trip.
     *
     * <p>It cost two hundred: every row went as its own RPC, because several
     * of them in one message were thought to need the same parameter types
     * throughout. They do not - each call in a TDS batch carries its own
     * types, which is why every second row here passes a {@code null} where
     * the others pass text.
     *
     * <p>Since the statement is compiled once and then addressed by handle
     * ({@code sp_prepexec} then {@code sp_execute}), the <b>first</b> batch
     * costs two: one to compile, one for the rest. Every batch after it costs
     * one. That is the trade - a round trip once per statement against the
     * full statement text and parameter declaration on every single row,
     * which is what {@code sp_executesql} carries.
     */
    @Test
    void aBatchOfTwoHundredRowsCostsOneRoundTrip() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("if object_id('zl_batch') is not null drop table zl_batch");
                statement.execute("create table zl_batch (n int, t nvarchar(50) null)");
            }
            try {
                connection.setAutoCommit(false);
                // The switch rides along with the next batch statement, so it
                // is sent here and not counted against the batch below.
                try (Statement warmup = connection.createStatement();
                     ResultSet ignored = warmup.executeQuery("select 1")) {
                    assertTrue(ignored.next());
                }
                try (PreparedStatement insert = connection.prepareStatement(
                        "insert into zl_batch values (?, ?)")) {
                    for (int i = 1; i <= 200; i++) {
                        insert.setInt(1, i);
                        if (i % 2 == 0) {
                            insert.setNull(2, Types.NVARCHAR);
                        } else {
                            insert.setString(2, "row " + i);
                        }
                        insert.addBatch();
                    }
                    long before = RoundTrips.of(connection);
                    int[] counts = insert.executeBatch();
                    assertEquals(2, RoundTrips.of(connection) - before,
                            "the first batch compiles the statement, then sends the rest");
                    assertEquals(200, counts.length);
                    for (int count : counts) {
                        assertEquals(1, count, "every row reports its own count");
                    }

                    // And the point of the handle: the SECOND batch on the
                    // same statement needs no compile. Two hundred more rows,
                    // one round trip - which is the invariant worth pinning,
                    // because a driver that re-prepares every time would pass
                    // the assertion above and fail this one.
                    for (int i = 201; i <= 400; i++) {
                        insert.setInt(1, i);
                        if (i % 2 == 0) {
                            insert.setNull(2, Types.NVARCHAR);
                        } else {
                            insert.setString(2, "row " + i);
                        }
                        insert.addBatch();
                    }
                    long beforeSecond = RoundTrips.of(connection);
                    assertEquals(200, insert.executeBatch().length);
                    assertEquals(1, RoundTrips.of(connection) - beforeSecond,
                            "a prepared statement must not compile twice");
                }
                connection.commit();
                try (Statement statement = connection.createStatement();
                     ResultSet rows = statement.executeQuery(
                             "select count(*), count(t), sum(cast(n as bigint)) from zl_batch")) {
                    assertTrue(rows.next());
                    // Both batches: 400 rows, 1..400, every second one null.
                    assertEquals(400, rows.getInt(1), "rows lost");
                    assertEquals(200, rows.getInt(2), "the nulls did not stay null");
                    assertEquals(80200L, rows.getLong(3), "the values changed");
                }
            } finally {
                connection.setAutoCommit(true);
                try (Statement statement = connection.createStatement()) {
                    statement.execute("if object_id('zl_batch') is not null drop table zl_batch");
                }
            }
        }
    }

    /**
     * How many rows a <b>different</b> connection can see.
     *
     * <p>{@code readpast} is not decoration. SQL Server locks rather than
     * versions: a plain count would not answer "one row is not visible yet",
     * it would wait for the open transaction - forever, since nothing sets a
     * lock timeout. {@code readpast} steps over what is locked, which is
     * exactly the question being asked here: what has already been committed.
     */
    private static int rowsSeenElsewhere() throws SQLException {
        try (Connection reader = connect();
             Statement statement = reader.createStatement();
             ResultSet found = statement.executeQuery(
                     "select count(*) from zl_commit with (readpast)")) {
            found.next();
            return found.getInt(1);
        }
    }

    @Test
    void logsInAndAnswers() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("select 1 + 1, @@version")) {
            assertTrue(result.next());
            assertEquals(2, result.getInt(1));
            assertNotNull(result.getString(2));
            assertFalse(result.next());
        }
    }

    /**
     * Values there and back - the point where a wrong length or a misread
     * type description turns into plausible nonsense rather than an error.
     */
    @Test
    void writesAndReadsTheTypesItClaimsToSupport() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_values') is not null drop table zl_values");
            statement.execute("""
                    create table zl_values (
                        id int identity primary key,
                        name nvarchar(40),
                        amount decimal(10,2),
                        weight float,
                        created datetime2(3),
                        day date,
                        flag bit,
                        payload varbinary(16),
                        big nvarchar(max)
                    )""");

            try (PreparedStatement insert = connection.prepareStatement("""
                    insert into zl_values (name, amount, weight, created, day, flag,
                                           payload, big)
                    values (?, ?, ?, ?, ?, ?, ?, ?)""")) {
                insert.setString(1, "Grüße");
                insert.setBigDecimal(2, new BigDecimal("123.45"));
                insert.setDouble(3, 1.5);
                insert.setTimestamp(4, java.sql.Timestamp.valueOf("2026-09-07 14:30:15.250"));
                insert.setDate(5, java.sql.Date.valueOf("2026-09-07"));
                insert.setBoolean(6, true);
                insert.setBytes(7, new byte[] {1, 2, 3});
                insert.setString(8, "x".repeat(5000));
                assertEquals(1, insert.executeUpdate());
            }

            try (Statement select = connection.createStatement();
                 ResultSet row = select.executeQuery("""
                     select name, amount, weight, created, day, flag, payload, big
                     from zl_values""")) {
                assertTrue(row.next());
                assertEquals("Grüße", row.getString("name"));
                assertEquals(0, new BigDecimal("123.45").compareTo(row.getBigDecimal("amount")));
                assertEquals(1.5, row.getDouble("weight"));
                assertEquals("2026-09-07 14:30:15.25",
                        row.getTimestamp("created").toString());
                assertEquals("2026-09-07", row.getDate("day").toString());
                assertTrue(row.getBoolean("flag"));
                assertEquals(3, row.getBytes("payload").length);
                // nvarchar(max) travels in chunks - this is the PLP framing.
                assertEquals(5000, row.getString("big").length());
            }
            statement.execute("drop table zl_values");
        }
    }

    /** A parameter is a parameter - never text inside the statement. */
    @Test
    void takesAQuoteInAParameterWithoutFlinching() throws Exception {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement("select ? as v")) {
            statement.setString(1, "Robert'); drop table students; --");
            try (ResultSet row = statement.executeQuery()) {
                assertTrue(row.next());
                assertEquals("Robert'); drop table students; --", row.getString(1));
            }
        }
    }

    /** Several rows, so that the row loop is exercised rather than one row. */
    @Test
    void readsManyRows() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("""
                 select top 500 object_id, name from sys.all_objects order by object_id""")) {
            int count = 0;
            long previous = Long.MIN_VALUE;
            while (rows.next()) {
                long id = rows.getLong(1);
                assertTrue(id >= previous, "the rows are out of order");
                previous = id;
                assertNotNull(rows.getString(2));
                count++;
            }
            assertEquals(500, count);
        }
    }

    /** NULL has to arrive as NULL - and NBCROW is how the server likes to send it. */
    @Test
    void readsNullValues() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet row = statement.executeQuery(
                     "select cast(null as int) as a, cast(null as nvarchar(10)) as b, 1 as c")) {
            assertTrue(row.next());
            assertEquals(0, row.getInt("a"));
            assertTrue(row.wasNull());
            assertEquals(null, row.getString("b"));
            assertTrue(row.wasNull());
            assertEquals(1, row.getInt("c"));
            assertFalse(row.wasNull());
        }
    }

    @Test
    void rollsBack() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_tx') is not null drop table zl_tx");
            statement.execute("create table zl_tx (id int primary key)");
            connection.setAutoCommit(false);
            statement.executeUpdate("insert into zl_tx values (1)");
            connection.rollback();
            connection.setAutoCommit(true);
            try (ResultSet count = statement.executeQuery("select count(*) from zl_tx")) {
                assertTrue(count.next());
                assertEquals(0, count.getInt(1));
            }
            statement.execute("drop table zl_tx");
        }
    }

    /** {@code scope_identity()} - and deliberately not {@code @@identity}. */
    @Test
    void reportsTheGeneratedKey() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_keys') is not null drop table zl_keys");
            statement.execute("create table zl_keys (id int identity primary key, "
                    + "name nvarchar(10))");
            statement.executeUpdate("insert into zl_keys (name) values ('a')");
            try (ResultSet keys = statement.getGeneratedKeys()) {
                assertTrue(keys.next());
                assertEquals(1, keys.getInt(1));
            }
            statement.execute("drop table zl_keys");
        }
    }

    /**
     * The same, through a {@code PreparedStatement} - and the second insert is
     * the whole test.
     *
     * <p>A prepared statement runs inside {@code sp_executesql}, a scope of its
     * own, so a {@code SCOPE_IDENTITY()} asked afterwards reports what the
     * <em>outer</em> scope last inserted. That used to return the first row's
     * key for the second row: not an error, a wrong answer, and Hibernate's
     * "null identifier" on a connection that had inserted nothing yet. One
     * insert alone would still pass with the bug in place, which is why there
     * are two here.
     */
    @Test
    void reportsTheGeneratedKeyOfAPreparedInsertAndNotThePreviousOne() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_prepared_keys') is not null "
                    + "drop table zl_prepared_keys");
            statement.execute("create table zl_prepared_keys (id int identity primary key, "
                    + "name nvarchar(10))");

            long[] seen = new long[2];
            for (int i = 0; i < 2; i++) {
                try (PreparedStatement insert = connection.prepareStatement(
                        "insert into zl_prepared_keys (name) values (?)",
                        Statement.RETURN_GENERATED_KEYS)) {
                    insert.setString(1, "row" + i);
                    assertEquals(1, insert.executeUpdate(),
                            "the count has to be the insert's, not the identity select's");
                    try (ResultSet keys = insert.getGeneratedKeys()) {
                        assertTrue(keys.next(), "an identity insert has a key");
                        seen[i] = keys.getLong(1);
                    }
                }
            }
            assertEquals(1, seen[0]);
            assertEquals(2, seen[1], "the second insert's key, not the first one's again");

            // And what the table actually holds has to agree with what was reported.
            try (ResultSet rows = statement.executeQuery(
                    "select id, name from zl_prepared_keys order by id")) {
                assertTrue(rows.next());
                assertEquals(1, rows.getInt(1));
                assertEquals("row0", rows.getString(2));
                assertTrue(rows.next());
                assertEquals(2, rows.getInt(1));
                assertEquals("row1", rows.getString(2));
            }
            statement.execute("drop table zl_prepared_keys");
        }
    }

    /**
     * Asking for keys that were never requested is refused rather than
     * answered with somebody else's - the shape the bug above had.
     */
    @Test
    void aStatementNotPreparedForKeysRefusesToInventThem() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_nokeys') is not null drop table zl_nokeys");
            statement.execute("create table zl_nokeys (id int identity primary key, "
                    + "name nvarchar(10))");
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_nokeys (name) values (?)")) {
                insert.setString(1, "a");
                insert.executeUpdate();
                SQLException refused = org.junit.jupiter.api.Assertions.assertThrows(
                        SQLException.class, insert::getGeneratedKeys);
                assertTrue(refused.getMessage().contains("RETURN_GENERATED_KEYS"),
                        refused.getMessage());
            }
            statement.execute("drop table zl_nokeys");
        }
    }

    /** An error has to arrive as an error, with its number and SQLState. */
    @Test
    void reportsAnErrorWithItsNumber() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_unique') is not null drop table zl_unique");
            statement.execute("create table zl_unique (id int primary key)");
            statement.executeUpdate("insert into zl_unique values (1)");
            SQLException failure = org.junit.jupiter.api.Assertions.assertThrows(
                    SQLException.class,
                    () -> statement.executeUpdate("insert into zl_unique values (1)"));
            assertEquals(2627, failure.getErrorCode());
            assertEquals("23000", failure.getSQLState());
            // The connection has to survive the error - the token stream was
            // read to its end before the exception was raised.
            try (ResultSet count = statement.executeQuery("select count(*) from zl_unique")) {
                assertTrue(count.next());
                assertEquals(1, count.getInt(1));
            }
            statement.execute("drop table zl_unique");
        }
    }

    @Test
    void theColumnListNamesTheJdbcType() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_types') is not null drop table zl_types");
            statement.execute("""
                    create table zl_types (
                        id int primary key,
                        name nvarchar(40),
                        amount decimal(10,2),
                        created datetime2,
                        flag bit,
                        raw varbinary(8),
                        big nvarchar(max)
                    )""");
            Map<String, Integer> found = new HashMap<>();
            try (ResultSet columns = connection.getMetaData()
                    .getColumns(null, null, "zl_types", null)) {
                while (columns.next()) {
                    found.put(columns.getString("COLUMN_NAME"), columns.getInt("DATA_TYPE"));
                }
            }
            assertEquals(Types.INTEGER, found.get("id"));
            assertEquals(Types.VARCHAR, found.get("name"));
            assertEquals(Types.DECIMAL, found.get("amount"));
            assertEquals(Types.TIMESTAMP, found.get("created"));
            assertEquals(Types.BOOLEAN, found.get("flag"));
            assertEquals(Types.VARBINARY, found.get("raw"));
            assertEquals(Types.LONGVARCHAR, found.get("big"));
            statement.execute("drop table zl_types");
        }
    }

    @Test
    void theTypeListNamesRealJdbcTypes() throws Exception {
        try (Connection connection = connect();
             ResultSet types = connection.getMetaData().getTypeInfo()) {
            List<String> names = new ArrayList<>();
            int previous = Integer.MIN_VALUE;
            while (types.next()) {
                names.add(types.getString("TYPE_NAME"));
                int type = types.getInt("DATA_TYPE");
                assertTrue(type != 0, "the type list reports 0 for " + names.getLast());
                assertTrue(type >= previous, "the list is not ordered by DATA_TYPE");
                previous = type;
            }
            assertTrue(names.contains("int"), "int is missing: " + names);
            assertTrue(names.contains("nvarchar"), "nvarchar is missing: " + names);
        }
    }

    @Test
    void describesKeys() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_child') is not null drop table zl_child");
            statement.execute("if object_id('zl_parent') is not null drop table zl_parent");
            statement.execute("create table zl_parent (id int primary key)");
            statement.execute("create table zl_child (id int primary key, parent_id int, "
                    + "constraint fk_parent foreign key (parent_id) "
                    + "references zl_parent (id))");

            DatabaseMetaData metaData = connection.getMetaData();
            try (ResultSet keys = metaData.getPrimaryKeys(null, null, "zl_parent")) {
                assertTrue(keys.next());
                assertEquals("id", keys.getString("COLUMN_NAME"));
            }
            try (ResultSet keys = metaData.getImportedKeys(null, null, "zl_child")) {
                assertTrue(keys.next(), "the foreign key of zl_child was not found");
                assertEquals("zl_parent", keys.getString("PKTABLE_NAME"));
                assertEquals("parent_id", keys.getString("FKCOLUMN_NAME"));
            }
            statement.execute("drop table zl_child");
            statement.execute("drop table zl_parent");
        }
    }

    // ---- procedure calls --------------------------------------------------

    /** An OUT parameter, through the declare/exec/select batch. */
    @Test
    void callsAProcedureAndReadsAnOutputParameter() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_double') is not null drop procedure zl_double");
            statement.execute("create procedure zl_double @n int, @doubled int output as "
                    + "set @doubled = @n * 2");
            try (CallableStatement call = connection.prepareCall("{call zl_double(?, ?)}")) {
                call.setInt(1, 21);
                call.registerOutParameter(2, Types.INTEGER);
                call.execute();
                assertEquals(42, call.getInt(2));
                assertFalse(call.wasNull());
            }
            statement.execute("drop procedure zl_double");
        }
    }

    /** An INOUT parameter: the value goes in and comes back changed. */
    @Test
    void callsAProcedureWithAnInOutParameter() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_grow') is not null drop procedure zl_grow");
            statement.execute("create procedure zl_grow @n int output as set @n = @n + 5");
            try (CallableStatement call = connection.prepareCall("{call zl_grow(?)}")) {
                call.registerOutParameter(1, Types.INTEGER);
                call.setInt(1, 37);
                call.execute();
                assertEquals(42, call.getInt(1));
            }
            statement.execute("drop procedure zl_grow");
        }
    }

    /** Two outputs of different types, so neither can pass by landing on the other. */
    @Test
    void callsAProcedureWithTwoOutputsOfDifferentTypes() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_split') is not null drop procedure zl_split");
            statement.execute("create procedure zl_split @whole nvarchar(50), "
                    + "@head nvarchar(50) output, @count int output as begin "
                    + "set @head = left(@whole, charindex('-', @whole) - 1); "
                    + "set @count = len(@whole); end");
            try (CallableStatement call = connection.prepareCall("{call zl_split(?, ?, ?)}")) {
                call.setString(1, "left-right");
                call.registerOutParameter(2, Types.VARCHAR);
                call.registerOutParameter(3, Types.INTEGER);
                call.execute();
                assertEquals("left", call.getString(2));
                assertEquals(10, call.getInt(3));
            }
            statement.execute("drop procedure zl_split");
        }
    }

    /** A scalar function, where parameter 1 is the return value. */
    @Test
    void callsAFunctionAndReadsItsReturnValue() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_triple') is not null drop function zl_triple");
            statement.execute("create function zl_triple(@n int) returns int as "
                    + "begin return @n * 3 end");
            try (CallableStatement call = connection.prepareCall("{? = call dbo.zl_triple(?)}")) {
                call.registerOutParameter(1, Types.INTEGER);
                call.setInt(2, 14);
                call.execute();
                assertEquals(42, call.getInt(1));
            }
            statement.execute("drop function zl_triple");
        }
    }

    /** An output that came back NULL says so rather than reading as zero. */
    @Test
    void anOutputThatIsNullSaysSo() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_nothing') is not null drop procedure zl_nothing");
            statement.execute("create procedure zl_nothing @n int output as set @n = null");
            try (CallableStatement call = connection.prepareCall("{call zl_nothing(?)}")) {
                call.registerOutParameter(1, Types.INTEGER);
                call.execute();
                assertEquals(0, call.getInt(1));
                assertTrue(call.wasNull());
            }
            statement.execute("drop procedure zl_nothing");
        }
    }

    /**
     * Parameters addressed by the name the procedure declared.
     *
     * <p>The arguments are set in the wrong order on purpose and the
     * procedure subtracts, so a driver that ignored the names and filled the
     * positions in the order it was called would answer 60 rather than -60.
     * One name is passed with the {@code @} SQL Server writes it with and one
     * without, because an application may well do either.
     */
    @Test
    void addressesParametersByName() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_minus') is not null drop procedure zl_minus");
            statement.execute("create procedure zl_minus @base int, @minus int, "
                    + "@answer int output as set @answer = @base - @minus");
            try (CallableStatement call = connection.prepareCall("{call zl_minus(?, ?, ?)}")) {
                call.setInt("@minus", 100);
                call.setInt("base", 40);
                call.registerOutParameter("answer", Types.INTEGER);
                call.execute();
                assertEquals(-60, call.getInt("@answer"));
            }
            statement.execute("drop procedure zl_minus");
        }
    }

    /**
     * The catalog describes a procedure, which is what a call framework reads.
     *
     * <p>SQL Server knows no {@code INOUT}: a parameter declared
     * {@code output} can be read and written, and the catalog says
     * {@code INOUT} for it. So the two outputs here both come back as
     * {@code procedureColumnInOut}, and that is the server's answer rather
     * than a shortcut of ours.
     */
    @Test
    void describesAProceduresParameters() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("if object_id('zl_described') is not null "
                    + "drop procedure zl_described");
            statement.execute("create procedure zl_described @n int, @doubled int output, "
                    + "@note varchar(10) output as set @doubled = @n * 2");
            List<String> described = new ArrayList<>();
            try (ResultSet columns = connection.getMetaData()
                    .getProcedureColumns(null, null, "zl_described", null)) {
                while (columns.next()) {
                    described.add(columns.getString("COLUMN_NAME") + " "
                            + columns.getShort("COLUMN_TYPE") + " "
                            + columns.getInt("DATA_TYPE"));
                }
            }
            assertEquals(List.of("@n 1 4", "@doubled 2 4", "@note 2 12"), described);
            statement.execute("drop procedure zl_described");
        }
    }
}
