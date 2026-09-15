package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

import space.seclume.Pipeline;
import space.seclume.RoundTrips;

/**
 * The MySQL driver against a <b>real</b> server.
 *
 * <p>{@code ProtocolTest} checks the framing against a server this project
 * wrote itself - which proves that the driver is consistent, not that it is
 * right. Only a real MySQL can say the latter, and it says it about the things
 * that a self-written server would happily get wrong in the same way: the
 * login, the type descriptions in the answer, and the catalog queries behind
 * {@code DatabaseMetaData}.
 *
 * <p>The URL carries no password, only where to find one.
 *
 * <p>Without a reachable server the test is skipped, not failed. To start one:
 * {@code podman run -d --name seclume-mysql --env-file … -p 3307:3306
 * docker.io/library/mysql:8.4}.
 */
class LocalMySqlTest {

    private static final String HOST = System.getProperty("seclume.mysql.host",
            "db.example.invalid");
    private static final int PORT = Integer.getInteger("seclume.mysql.port", 3307);
    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mysql-password"),
                Path.of("..", ".local-mysql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mysql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no MySQL on " + HOST + ":" + PORT);
        }
        // allowPublicKeyRetrieval: MySQL 8 authenticates a user's first
        // connection the long way round - it wants the password itself, RSA
        // encrypted with a key the client has to ask for. Asking an
        // unauthenticated server for a key is what a man in the middle would
        // answer, which is why the driver refuses it unless told otherwise.
        // Here it is deliberate: a throwaway server on the local network, and
        // the only way to exercise our own RSA and OAEP against a real MySQL
        // instead of against our own arithmetic.
        url = "jdbc:seclume:mysql://" + HOST + ":" + PORT + "/" + DATABASE
                + "?user=" + USER + "&allowPublicKeyRetrieval=true&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(url);
    }

    /**
     * Five writes, one round trip.
     *
     * <p>Counted, not timed: five statements sent one by one cost five round
     * trips, and over a network that is the whole of the time. See
     * {@link space.seclume.Pipeline}.
     */
    @Test
    void aPipelineBlockCostsOneRoundTripForTheWholeUnitOfWork() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists zl_pipe");
                statement.execute("create table zl_pipe (n int) engine=innodb");
            }
            try {
                connection.setAutoCommit(false);
                try (PreparedStatement insert =
                             connection.prepareStatement("insert into zl_pipe values (?)")) {
                    insert.setInt(1, 0);            // once, so the plan is on the server
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
                    assertEquals(1, RoundTrips.of(connection) - before,
                            "five writes have to cost one round trip");
                    connection.commit();
                }
                connection.setAutoCommit(true);
                try (Statement statement = connection.createStatement();
                     ResultSet rows = statement.executeQuery("select count(*) from zl_pipe")) {
                    assertTrue(rows.next());
                    assertEquals(6, rows.getInt(1));
                }
            } finally {
                connection.setAutoCommit(true);
                try (Statement statement = connection.createStatement()) {
                    statement.execute("drop table if exists zl_pipe");
                }
            }
        }
    }

    /**
     * {@code getTables} with a type filter - the call Hibernate makes.
     *
     * <p>It found nothing for a while, and the reason is a vocabulary: JDBC
     * says {@code TABLE}, MySQL's {@code information_schema} says
     * {@code BASE TABLE}. An application with {@code ddl-auto=validate} then
     * refused to start with "missing table" for a table that was right there -
     * and no driver test noticed, because none of them passed a type filter.
     */
    @Test
    void getTablesFindsATableWithAndWithoutATypeFilter() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists zl_types");
                statement.execute("create table zl_types (n int) engine=innodb");
            }
            try {
                DatabaseMetaData meta = connection.getMetaData();
                assertTrue(hasTable(meta.getTables(null, null, "zl_types", null)),
                        "not even without a filter");
                assertTrue(hasTable(meta.getTables(null, null, "zl_types",
                                new String[] {"TABLE"})),
                        "a type filter of TABLE has to find an ordinary table");

                // And the type it reports has to be the word it accepts.
                try (ResultSet tables = meta.getTables(null, null, "zl_types", null)) {
                    assertTrue(tables.next());
                    assertEquals("TABLE", tables.getString("TABLE_TYPE"));
                }
                try (ResultSet types = meta.getTableTypes()) {
                    boolean sawTable = false;
                    while (types.next()) {
                        sawTable |= "TABLE".equals(types.getString("TABLE_TYPE"));
                    }
                    assertTrue(sawTable, "getTableTypes has to offer the word getTables takes");
                }
            } finally {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("drop table if exists zl_types");
                }
            }
        }
    }

    private static boolean hasTable(ResultSet tables) throws SQLException {
        try (ResultSet rows = tables) {
            return rows.next();
        }
    }

    /**
     * A big result is read in blocks, not all at once.
     *
     * <p>MySQL keeps the rows in a <b>server-side cursor</b>: the execute
     * brings the column descriptions and nothing else, and each
     * {@code COM_STMT_FETCH} brings one block. The flag in the closing EOF of
     * a block says whether it was the last - reading it is the whole trick.
     */
    @Test
    void aFetchSizeReadsTheResultInBlocks() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists zl_blocks");
                statement.execute("create table zl_blocks (n int) engine=innodb");
                statement.execute("insert into zl_blocks "
                        + "with recursive s(n) as (select 1 union all select n + 1 from s "
                        + "where n < 1000) select n from s");
            }
            try (PreparedStatement query = connection.prepareStatement(
                    "select n from zl_blocks order by n")) {
                query.setFetchSize(100);
                int seen = 0;
                long sum = 0;
                try (ResultSet rows = query.executeQuery()) {
                    while (rows.next()) {
                        seen++;
                        assertEquals(seen, rows.getInt(1), "the rows arrived out of order");
                        sum += rows.getInt(1);
                    }
                }
                assertEquals(1000, seen, "rows lost");
                assertEquals(500500L, sum, "the values changed");
            } finally {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("drop table if exists zl_blocks");
                }
            }
        }
    }

    /**
     * A result that runs away ends in an error that names the query - not in
     * an {@code OutOfMemoryError} that names an allocation.
     */
    @Test
    void aResultLargerThanTheLimitIsRefused() throws Exception {
        String bounded = url + "&maxResultRows=10";
        try (Connection connection = DriverManager.getConnection(bounded);
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists zl_limit");
            statement.execute("create table zl_limit (n int)");
            try {
                for (int i = 0; i < 40; i++) {
                    statement.execute("insert into zl_limit values (" + i + ")");
                }
                SQLException thrown = assertThrows(SQLException.class,
                        () -> statement.executeQuery("select n from zl_limit"));
                assertEquals("54001", thrown.getSQLState());
                assertTrue(thrown.getMessage().contains("zl_limit"), thrown.getMessage());
            } finally {
                statement.execute("drop table if exists zl_limit");
            }
        }
    }

    /**
     * What the common shapes cost, counted rather than timed.
     *
     * <p>A number that does not depend on the network: a change that adds a
     * round trip fails here in a second instead of showing up as a vague
     * slowdown in production. See {@link space.seclume.RoundTrips}.
     *
     * <p>The second transaction is the interesting one: the plan is in the
     * connection's cache by then, so it costs the statement and the commit and
     * nothing else - even though the application built a fresh
     * {@code PreparedStatement}, which is what every framework does.
     */
    @Test
    void countsTheRoundTripsOfTheCommonShapes() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists zl_trips");
                statement.execute("create table zl_trips (n int, t varchar(40))");
            }

            insertOnce(connection);              // warms the plan cache
            long before = RoundTrips.of(connection);
            insertOnce(connection);
            assertEquals(2, RoundTrips.of(connection) - before,
                    "a transaction with one statement is the statement and the commit");

            before = RoundTrips.of(connection);
            connection.setReadOnly(true);
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            connection.setReadOnly(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            assertEquals(0, RoundTrips.of(connection) - before,
                    "settings ride along with the next statement");

            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table zl_trips");
            }
        }
    }

    /** One transaction, one statement - through a fresh statement object. */
    private static void insertOnce(Connection connection) throws SQLException {
        connection.setAutoCommit(false);
        try (PreparedStatement insert = connection.prepareStatement(
                "insert into zl_trips values (?, ?)")) {
            insert.setInt(1, 1);
            insert.setString(2, "x");
            insert.executeUpdate();
        }
        connection.commit();
        connection.setAutoCommit(true);
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

    /**
     * A batch larger than one pipeline group, inside a transaction.
     *
     * <p>The commands go out back to back and the answers are read afterwards,
     * so the n-th answer has to land on the n-th row. Six hundred rows cross
     * the group boundary at least twice - that is where a driver miscounts if
     * it is going to. The second half checks that a failing batch still leaves
     * the connection usable: the answers to the rows already sent have to be
     * read, or the next command reads them instead.
     */
    @Test
    void aBatchIsPipelinedAndStillCountsEveryRow() throws Exception {
        int rows = 600;
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists seclume_pipeline");
                statement.execute("create table seclume_pipeline (n int, t varchar(40))");
            }
            connection.setAutoCommit(false);
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
            connection.commit();
            connection.setAutoCommit(true);

            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery(
                         "select count(*), sum(n), min(t) from seclume_pipeline")) {
                assertTrue(result.next());
                assertEquals(rows, result.getInt(1));
                assertEquals(rows * (rows - 1) / 2, result.getInt(2));
                assertEquals("row-0", result.getString(3));
            }
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table seclume_pipeline");
            }
            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("select 1")) {
                assertTrue(result.next(), "the connection is unusable after the batch");
            }
        }
    }

    /**
     * A batch really runs inside the transaction - checked by rolling it back.
     *
     * <p>This is the test that was missing, and the gap it left cost a factor
     * of forty. {@code setAutoCommit(false)} does not go to the server on its
     * own: it is announced and rides along with the next statement, which saves
     * a round trip. The batch path forgot to take it along, so five hundred
     * rows ran with autocommit still <b>on</b> - each one its own durable
     * transaction, each one an {@code fsync}, 1.9 ms per row.
     *
     * <p>Nothing about that was visible from the outside. The round trips were
     * perfect (two for five hundred rows), every row was inserted, every count
     * came back as 1, and the existing batch test passed - because it commits
     * at the end, and a row that committed itself earlier looks exactly the
     * same afterwards. Only a rollback can tell the two apart.
     *
     * <p>So: insert, roll back, and the table has to be empty. If autocommit
     * is on, the rows survive and this test says so.
     */
    @Test
    void aBatchRunsInsideTheTransactionAndRollsBackWithIt() throws Exception {
        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table if exists seclume_batch_tx");
                statement.execute(
                        "create table seclume_batch_tx (n int) engine=innodb");
            }
            connection.setAutoCommit(false);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into seclume_batch_tx values (?)")) {
                for (int i = 0; i < 20; i++) {
                    insert.setInt(1, i);
                    insert.addBatch();
                }
                assertEquals(20, insert.executeBatch().length);
            }
            connection.rollback();
            connection.setAutoCommit(true);

            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery(
                         "select count(*) from seclume_batch_tx")) {
                assertTrue(result.next());
                assertEquals(0, result.getInt(1),
                        "the batch ran with autocommit on - the rows survived a rollback");
            }
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table seclume_batch_tx");
            }
        }
    }

    /** Logging in with {@code caching_sha2_password} - MySQL 8's default. */
    @Test
    void logsInAndAnswers() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("select 1 + 1, version()")) {
            assertTrue(result.next());
            assertEquals(2, result.getInt(1));
            assertNotNull(result.getString(2));
            assertFalse(result.next());
        }
    }

    /** Values there and back - the point where an encoding error shows up. */
    @Test
    void writesAndReadsEveryTypeItClaimsToSupport() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists zl_values");
            statement.execute("""
                    create table zl_values (
                        id int primary key auto_increment,
                        name varchar(40),
                        amount decimal(10,2),
                        weight double,
                        created datetime,
                        day date,
                        flag tinyint(1),
                        payload varbinary(16)
                    )""");

            try (PreparedStatement insert = connection.prepareStatement("""
                    insert into zl_values (name, amount, weight, created, day, flag, payload)
                    values (?, ?, ?, ?, ?, ?, ?)""")) {
                insert.setString(1, "Grüße");
                insert.setBigDecimal(2, new BigDecimal("123.45"));
                insert.setDouble(3, 1.5);
                insert.setTimestamp(4, java.sql.Timestamp.valueOf("2026-09-07 14:30:15"));
                insert.setDate(5, java.sql.Date.valueOf("2026-09-07"));
                insert.setBoolean(6, true);
                insert.setBytes(7, new byte[] {1, 2, 3});
                assertEquals(1, insert.executeUpdate());
            }

            try (PreparedStatement select = connection.prepareStatement(
                    "select name, amount, weight, created, day, flag, payload from zl_values");
                 ResultSet row = select.executeQuery()) {
                assertTrue(row.next());
                assertEquals("Grüße", row.getString("name"));
                assertEquals(0, new BigDecimal("123.45").compareTo(row.getBigDecimal("amount")));
                assertEquals(1.5, row.getDouble("weight"));
                assertEquals("2026-09-07 14:30:15.0", row.getTimestamp("created").toString());
                assertEquals("2026-09-07", row.getDate("day").toString());
                assertTrue(row.getBoolean("flag"));
                assertEquals(3, row.getBytes("payload").length);
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

    /** Rolling back has to undo, not merely report. */
    @Test
    void rollsBack() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists zl_tx");
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

    /** The key that {@code auto_increment} just handed out. */
    @Test
    void reportsTheGeneratedKey() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists zl_keys");
            statement.execute("create table zl_keys (id int primary key auto_increment, "
                    + "name varchar(10))");
            statement.executeUpdate("insert into zl_keys (name) values ('a')");
            try (ResultSet keys = statement.getGeneratedKeys()) {
                assertTrue(keys.next());
                assertEquals(1, keys.getInt(1));
            }
            statement.execute("drop table zl_keys");
        }
    }

    /**
     * {@code getColumns} has to name the JDBC type, not a placeholder -
     * Hibernate compares the schema against it, and Flyway plans migrations
     * with it.
     */
    @Test
    void theColumnListNamesTheJdbcType() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists zl_types");
            statement.execute("""
                    create table zl_types (
                        id int primary key,
                        name varchar(40),
                        amount decimal(10,2),
                        created datetime,
                        body text,
                        raw varbinary(8)
                    )""");
            DatabaseMetaData metaData = connection.getMetaData();
            Map<String, Integer> found = new HashMap<>();
            try (ResultSet columns = metaData.getColumns(null, null, "zl_types", null)) {
                while (columns.next()) {
                    found.put(columns.getString("COLUMN_NAME"), columns.getInt("DATA_TYPE"));
                }
            }
            assertEquals(Types.INTEGER, found.get("id"));
            assertEquals(Types.VARCHAR, found.get("name"));
            assertEquals(Types.DECIMAL, found.get("amount"));
            assertEquals(Types.TIMESTAMP, found.get("created"));
            assertEquals(Types.LONGVARCHAR, found.get("body"));
            assertEquals(Types.VARBINARY, found.get("raw"));
            statement.execute("drop table zl_types");
        }
    }

    /** The type list, ordered by DATA_TYPE as JDBC prescribes. */
    @Test
    void theTypeListNamesRealJdbcTypes() throws Exception {
        try (Connection connection = connect();
             ResultSet types = connection.getMetaData().getTypeInfo()) {
            List<String> names = new ArrayList<>();
            int previous = Integer.MIN_VALUE;
            while (types.next()) {
                names.add(types.getString("TYPE_NAME"));
                int type = types.getInt("DATA_TYPE");
                assertTrue(type != 0,
                        "the type list still reports 0 for " + types.getString("TYPE_NAME"));
                assertTrue(type >= previous, "the list is not ordered by DATA_TYPE");
                previous = type;
            }
            assertTrue(names.contains("int"), "int is missing: " + names);
            assertTrue(names.contains("varchar"), "varchar is missing: " + names);
            assertTrue(names.contains("datetime"), "datetime is missing: " + names);
        }
    }

    /** Primary and foreign keys - Hibernate reads both when validating. */
    @Test
    void describesKeys() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists zl_child");
            statement.execute("drop table if exists zl_parent");
            statement.execute("create table zl_parent (id int primary key)");
            statement.execute("create table zl_child (id int primary key, "
                    + "parent_id int, constraint fk_parent foreign key (parent_id) "
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
}
