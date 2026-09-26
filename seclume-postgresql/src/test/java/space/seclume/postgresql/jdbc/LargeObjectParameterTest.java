package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.tck.TestHosts;

/**
 * Blob and Clob parameters on PostgreSQL: a large object, and its oid as the
 * value - what Hibernate's {@code @Lob} mapping to {@code oid} depends on.
 *
 * <p>Refused until now, on the argument that a large object outlives its row.
 * It does, with pgjdbc as well - that is PostgreSQL's model, and cleaning up
 * is the server's business ({@code lo_manage}, {@code vacuumlo}). What the
 * driver can decide is that the object and the row commit or roll back
 * together, so it binds one only inside a transaction.
 */
class LargeObjectParameterTest {

    private static String url;

    @BeforeAll
    static void server() {
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no PostgreSQL password file");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no PostgreSQL on " + host + ":" + port);
        }
        url = "jdbc:seclume:postgresql://" + host + ":" + port + "/seclume_test"
                + "?user=seclume_test&tls=off&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/');
    }

    @Test
    void blobAndClobBecomeLargeObjectsAndReadBack() throws Exception {
        byte[] picture = new byte[3 * 1024 * 1024]; // seclume-allow: test payload
        new java.util.Random(24).nextBytes(picture);
        String script = "select 1; -- ÄÖÜ 東京\n".repeat(20_000);
        try (Connection connection = DriverManager.getConnection(url)) {
            recreate(connection);
            connection.setAutoCommit(false);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_lo_param values (?, ?, ?)")) {
                insert.setInt(1, 1);
                insert.setBlob(2, new ByteArrayInputStream(picture), picture.length);
                insert.setClob(3, new StringReader(script));
                insert.executeUpdate();
                insert.setInt(1, 2);
                insert.setBlob(2, (java.sql.Blob) null);
                insert.setClob(3, (java.sql.Clob) null);
                insert.executeUpdate();
            }
            connection.commit();
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "select picture, script from zl_lo_param order by id")) {
                rows.next();
                assertArrayEquals(picture, rows.getBlob(1).getBinaryStream().readAllBytes());
                assertEquals(script, rows.getClob(2).getSubString(1, script.length()));
                try (java.io.Reader reader = rows.getCharacterStream(2)) {
                    StringBuilder text = new StringBuilder();
                    char[] chunk = new char[8192];
                    for (int n; (n = reader.read(chunk)) > 0; ) {
                        text.append(chunk, 0, n);
                    }
                    assertEquals(script, text.toString());
                }
                rows.next();
                assertEquals(null, rows.getBlob(1));
                assertEquals(null, rows.getClob(2));
            }
            connection.commit();
        }
    }

    /** A rollback takes the large object with it - the reason for the transaction rule. */
    @Test
    void aRollbackLeavesNoLargeObjectBehind() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            recreate(connection);
            long before = largeObjects(connection);
            connection.setAutoCommit(false);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_lo_param values (?, ?, null)")) {
                insert.setInt(1, 1);
                insert.setBlob(2, new ByteArrayInputStream(new byte[] {1, 2, 3}));
                insert.executeUpdate();
            }
            assertEquals(before + 1, largeObjects(connection));
            connection.rollback();
            connection.setAutoCommit(true);
            assertEquals(before, largeObjects(connection), "the rollback left the object behind");
        }
    }

    /** Under auto-commit it is refused before anything is created. */
    @Test
    void underAutoCommitNothingIsCreated() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            recreate(connection);
            long before = largeObjects(connection);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_lo_param values (1, ?, ?)")) {
                SQLException blob = assertThrows(SQLException.class, () ->
                        insert.setBlob(1, new ByteArrayInputStream(new byte[] {1})));
                assertTrue(blob.getMessage().contains("setAutoCommit(false)"), blob.getMessage());
                assertThrows(SQLException.class, () -> insert.setClob(2, new StringReader("x")));
            }
            assertEquals(before, largeObjects(connection));
        }
    }

    private static long largeObjects(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select count(*) from pg_largeobject_metadata")) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private static void recreate(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists zl_lo_param");
            statement.execute("create table zl_lo_param (id int primary key, picture oid, "
                    + "script oid)");
        }
    }
}
