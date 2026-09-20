package space.seclume.postgresql.jdbc;

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
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import space.seclume.tck.TestHosts;

/**
 * CockroachDB and YugabyteDB, with a password.
 *
 * <p>Both speak PostgreSQL's wire protocol, and the claim this file exists to
 * check is that "speaks the same protocol" holds all the way down - not only
 * for a {@code select 1} but for the login, which is where a compatible
 * server is most likely to differ, and where this driver's whole point lies.
 *
 * <p>Until now both were reached without authentication, and the tests that
 * needed a password skipped themselves. That was honest and useless: a server
 * that lets anyone in proves nothing about a driver built to keep a password
 * off the heap. Each of these tests therefore starts by asserting which
 * authentication method the server actually asked for - and the two ask for
 * different ones, which is itself the finding.
 *
 * <p>Neither server is started by the test. Point it at one with
 * {@code -Dseclume.crdb.host=...} or {@code -Dseclume.yb.host=...}, as
 * {@code TESTING.md} describes; without that the tests skip.
 */
class LocalPostgresFamilyTest {

    @Nested
    @DisplayName("CockroachDB")
    class Cockroach extends FamilyTests {

        Cockroach() {
            super(TestHosts.server("crdb", 26257),
                  // A secure CockroachDB has no unencrypted port at all, and
                  // its certificate is its own. require, not verify-full:
                  // what is being tested here is the login, not a trust store.
                  "require",
                  "scram-sha-256");
        }
    }

    @Nested
    @DisplayName("YugabyteDB")
    class Yugabyte extends FamilyTests {

        Yugabyte() {
            // YugabyteDB's password authentication defaults to md5 - the older
            // of the two, and the one PostgreSQL itself has been moving away
            // from. Saying so here rather than quietly accepting whatever
            // arrives is the difference between a test and a formality.
            super(TestHosts.server("yb", 5433), "off", "md5");
        }
    }

    /**
     * The same body for both, because the point is that it <i>is</i> the same.
     *
     * <p>Anything that only one of them can do would belong in its own class.
     * Nothing here is in that position yet, which is the result.
     */
    abstract static class FamilyTests {

        private final TestHosts.Server server;
        private final String tls;
        private final String expectedAuthentication;
        private final String table;

        FamilyTests(TestHosts.Server server, String tls, String expectedAuthentication) {
            this.server = server;
            this.tls = tls;
            this.expectedAuthentication = expectedAuthentication;
            this.table = "zl_family_" + server.key();
        }

        private String url() {
            Path password = locatePasswordFile(server.passwordFile());
            Assumptions.assumeTrue(TestHosts.isConfigured(server.key()),
                    "no seclume." + server.key() + ".host - skipping " + server.key());
            Assumptions.assumeTrue(password != null,
                    "no " + server.passwordFile() + " - skipping " + server.key());
            Assumptions.assumeTrue(reachable(server),
                    "nothing on " + server.host() + ":" + server.port());
            return "jdbc:seclume:postgresql://" + server.host() + ":" + server.port()
                    + "/" + server.database() + "?user=" + server.user()
                    + "&tls=" + tls + "&provider=file&path="
                    + password.toString().replace('\\', '/');
        }

        private Connection connect() throws SQLException {
            return DriverManager.getConnection(url());
        }

        /**
         * The login, which is the whole reason this file exists.
         *
         * <p>A password was demanded, the driver answered it, and the server
         * named the method it used. Without this assertion a server that had
         * silently fallen back to trust would pass every other test here.
         */
        @Test
        void theServerDemandedAPasswordAndGotOne() throws Exception {
            try (Connection connection = connect()) {
                String method = connection.unwrap(space.seclume.postgresql.PgSession.class)
                        .authenticationMethod();
                assertEquals(expectedAuthentication, method,
                        "the server authenticated with " + method
                        + " - if that is deliberate, the expectation here has to move with it");

                try (Statement statement = connection.createStatement();
                     ResultSet rows = statement.executeQuery("select current_user")) {
                    assertTrue(rows.next());
                    assertEquals(server.user(), rows.getString(1));
                }
            }
        }

        /**
         * And a wrong password is refused, which is the other half of the
         * proof: a server that accepts anything would pass the test above.
         *
         * <p>The wrong password is a real file with the wrong content, not a
         * missing one - a missing file fails before the driver ever dials,
         * and would prove nothing about the server.
         */
        @Test
        void aWrongPasswordIsRefused() throws Exception {
            Path wrongFile = Path.of("target", "wrong-" + server.key() + "-password");
            Files.createDirectories(wrongFile.getParent());
            Files.writeString(wrongFile, "not-the-password");
            String wrong = url().replaceAll("&path=[^&]*$",
                    "&path=" + wrongFile.toAbsolutePath().toString()
                            .replace(java.io.File.separatorChar, '/'));
            SQLException refused = assertThrows(SQLException.class,
                    () -> DriverManager.getConnection(wrong));
            assertNotNull(refused.getMessage());
        }

        @Test
        void writesAndReadsBackEveryOrdinaryType() throws Exception {
            UUID id = UUID.randomUUID();
            try (Connection connection = connect();
                 Statement ddl = connection.createStatement()) {
                ddl.execute("drop table if exists " + table);
                ddl.execute("create table " + table + " ("
                        + "id uuid primary key, name text not null, amount numeric(12,2), "
                        + "count bigint, flag boolean, at timestamp)");
                try {
                    try (PreparedStatement insert = connection.prepareStatement(
                            "insert into " + table + " values (?, ?, ?, ?, ?, ?)")) {
                        insert.setObject(1, id);
                        insert.setString(2, "a name with an umlaut: ä");
                        insert.setBigDecimal(3, new BigDecimal("1234.56"));
                        insert.setLong(4, 42);
                        insert.setBoolean(5, true);
                        insert.setTimestamp(6, java.sql.Timestamp.valueOf("2026-02-03 04:05:06"));
                        assertEquals(1, insert.executeUpdate());
                    }

                    try (PreparedStatement select = connection.prepareStatement(
                            "select name, amount, count, flag, at from " + table
                            + " where id = ?")) {
                        select.setObject(1, id);
                        try (ResultSet rows = select.executeQuery()) {
                            assertTrue(rows.next());
                            assertEquals("a name with an umlaut: ä", rows.getString(1));
                            assertEquals(0, new BigDecimal("1234.56").compareTo(
                                    rows.getBigDecimal(2)));
                            assertEquals(42, rows.getLong(3));
                            assertTrue(rows.getBoolean(4));
                            assertEquals("2026-02-03 04:05:06.0", rows.getTimestamp(5).toString());
                            assertFalse(rows.next());
                        }
                    }
                } finally {
                    ddl.execute("drop table if exists " + table);
                }
            }
        }

        /**
         * A transaction that is rolled back leaves nothing - checked over a
         * <b>second</b> connection, because a session sees its own uncommitted
         * writes and a check on the same one passes either way.
         */
        @Test
        void aRollbackLeavesNothingBehind() throws Exception {
            try (Connection writer = connect();
                 Statement ddl = writer.createStatement()) {
                ddl.execute("drop table if exists " + table);
                ddl.execute("create table " + table + " (id int primary key)");
                try {
                    writer.setAutoCommit(false);
                    try (Statement statement = writer.createStatement()) {
                        statement.executeUpdate("insert into " + table + " values (1)");
                    }
                    writer.rollback();
                    writer.setAutoCommit(true);

                    try (Connection reader = connect();
                         Statement statement = reader.createStatement();
                         ResultSet rows = statement.executeQuery(
                                 "select count(*) from " + table)) {
                        assertTrue(rows.next());
                        assertEquals(0, rows.getInt(1), "the rollback left a row behind");
                    }

                    try (Statement statement = writer.createStatement()) {
                        statement.executeUpdate("insert into " + table + " values (2)");
                    }
                    try (Connection reader = connect();
                         Statement statement = reader.createStatement();
                         ResultSet rows = statement.executeQuery(
                                 "select count(*) from " + table)) {
                        assertTrue(rows.next());
                        assertEquals(1, rows.getInt(1), "auto-commit did not commit");
                    }
                } finally {
                    ddl.execute("drop table if exists " + table);
                }
            }
        }

        /** Batches, because that is where a compatible server most often is not. */
        @Test
        void sendsABatchAndGetsTheCountsBack() throws Exception {
            try (Connection connection = connect();
                 Statement ddl = connection.createStatement()) {
                ddl.execute("drop table if exists " + table);
                ddl.execute("create table " + table + " (id int primary key, name text)");
                try {
                    try (PreparedStatement insert = connection.prepareStatement(
                            "insert into " + table + " values (?, ?)")) {
                        for (int i = 1; i <= 50; i++) {
                            insert.setInt(1, i);
                            insert.setString(2, "row " + i);
                            insert.addBatch();
                        }
                        int[] counts = insert.executeBatch();
                        assertEquals(50, counts.length);
                        for (int count : counts) {
                            assertTrue(count == 1 || count == Statement.SUCCESS_NO_INFO,
                                    "a batch entry reported " + count);
                        }
                    }
                    try (Statement statement = connection.createStatement();
                         ResultSet rows = statement.executeQuery(
                                 "select count(*) from " + table)) {
                        assertTrue(rows.next());
                        assertEquals(50, rows.getInt(1));
                    }
                } finally {
                    ddl.execute("drop table if exists " + table);
                }
            }
        }

        /**
         * The catalogue, far enough that Hibernate's validation and Flyway
         * work - which is what an application actually needs from a
         * compatible server.
         */
        @Test
        void theCatalogueDescribesATableItJustCreated() throws Exception {
            try (Connection connection = connect();
                 Statement ddl = connection.createStatement()) {
                ddl.execute("drop table if exists " + table);
                ddl.execute("create table " + table
                        + " (id int primary key, name varchar(40) not null)");
                try {
                    DatabaseMetaData catalogue = connection.getMetaData();
                    assertNotNull(catalogue.getDatabaseProductName());
                    assertNotNull(catalogue.getDatabaseProductVersion());

                    List<String> columns = new ArrayList<>();
                    try (ResultSet rows = catalogue.getColumns(null, null, table, null)) {
                        while (rows.next()) {
                            columns.add(rows.getString("COLUMN_NAME"));
                        }
                    }
                    assertEquals(List.of("id", "name"), columns);

                    try (ResultSet keys = catalogue.getPrimaryKeys(null, null, table)) {
                        assertTrue(keys.next(), "no primary key reported");
                        assertEquals("id", keys.getString("COLUMN_NAME"));
                    }
                } finally {
                    ddl.execute("drop table if exists " + table);
                }
            }
        }

        /** A fetch size, so the block cursor is exercised and not only assumed. */
        @Test
        void readsAResultInBlocks() throws Exception {
            try (Connection connection = connect();
                 Statement ddl = connection.createStatement()) {
                ddl.execute("drop table if exists " + table);
                ddl.execute("create table " + table + " (id int primary key)");
                try {
                    try (PreparedStatement insert = connection.prepareStatement(
                            "insert into " + table + " values (?)")) {
                        for (int i = 1; i <= 300; i++) {
                            insert.setInt(1, i);
                            insert.addBatch();
                        }
                        insert.executeBatch();
                    }
                    connection.setAutoCommit(false);
                    try (Statement statement = connection.createStatement()) {
                        statement.setFetchSize(25);
                        try (ResultSet rows = statement.executeQuery(
                                "select id from " + table + " order by id")) {
                            int seen = 0;
                            while (rows.next()) {
                                seen++;
                                assertEquals(seen, rows.getInt(1));
                            }
                            assertEquals(300, seen, "rows lost across a block boundary");
                        }
                    }
                    connection.commit();
                    connection.setAutoCommit(true);
                } finally {
                    ddl.execute("drop table if exists " + table);
                }
            }
        }

        private static Path locatePasswordFile(String name) {
            for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
                if (Files.exists(candidate)) {
                    return candidate.toAbsolutePath().normalize();
                }
            }
            return null;
        }

        private static String noSuchFile() {
            return Path.of("target", "no-such-password").toAbsolutePath()
                    .toString().replace('\\', '/');
        }

        private static boolean reachable(TestHosts.Server server) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(server.host(), server.port()), 2000);
                return true;
            } catch (IOException unreachable) {
                return false;
            }
        }
    }
}
