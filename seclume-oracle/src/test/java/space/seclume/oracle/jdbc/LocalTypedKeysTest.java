package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
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
import java.sql.Types;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Generated keys that are not numbers: a VARCHAR2 made by a default, a RAW
 * from {@code sys_guid()} - a UUID as Oracle keeps one - and the ROWID. Bound
 * as NUMBER, as every key was, the first is ORA-01722 and the RAW comes back
 * as digits. The key columns are described once and bound with their types;
 * a NUMBER key stays a {@code Long} for Spring's KeyHolder.
 */
@Timeout(120)
class LocalTypedKeysTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:oracle://" + HOST + ":" + PORT + "/"
                + System.getProperty("seclume.oracle.service", "FREEPDB1")
                + "?user=seclume_test&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    private static void recreate(Statement statement) throws SQLException {
        try {
            statement.execute("drop table zl_typed_keys purge");
        } catch (SQLException absent) {
            // first run
        }
        statement.execute("create table zl_typed_keys ("
                + "id number generated always as identity primary key, "
                + "code varchar2(40) default 'K-' || rawtohex(sys_guid()) not null, "
                + "guid raw(16) default sys_guid() not null, "
                + "title varchar2(100))");
    }

    @Test
    void numberTextAndRawKeysComeBackAsWhatTheyAre() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            recreate(statement);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_typed_keys (title) values (?)",
                    new String[] {"id", "code", "guid"})) {
                for (int i = 1; i <= 3; i++) {                 // the described types, reused
                    insert.setString(1, "row " + i);
                    assertEquals(1, insert.executeUpdate());
                    try (ResultSet keys = insert.getGeneratedKeys()) {
                        assertTrue(keys.next());
                        assertEquals((long) i, keys.getObject(1), "a NUMBER key is a Long");
                        assertEquals(i, keys.getLong("id"));
                        String code = keys.getString(2);
                        assertTrue(code.matches("K-[0-9A-F]{32}"), code);
                        assertInstanceOf(String.class, keys.getObject("code"));
                        byte[] guid = keys.getBytes(3);
                        assertEquals(16, guid.length);
                        assertEquals(Types.NUMERIC, keys.getMetaData().getColumnType(1));
                        assertEquals(Types.VARCHAR, keys.getMetaData().getColumnType(2));
                        assertEquals(Types.VARBINARY, keys.getMetaData().getColumnType(3));
                        assertThrows(SQLException.class, () -> keys.getLong(2));

                        try (PreparedStatement check = connection.prepareStatement(
                                "select code, guid from zl_typed_keys where id = ?")) {
                            check.setLong(1, i);
                            try (ResultSet row = check.executeQuery()) {
                                assertTrue(row.next());
                                assertEquals(row.getString(1), code);
                                assertArrayEquals(row.getBytes(2), guid);
                            }
                        }
                    }
                }
            }
        }
    }

    /** The ROWID as its text, which finds the row again; and an update's returning. */
    @Test
    void theRowidAndAnUpdatesReturning() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            recreate(statement);
            String rowid;
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_typed_keys (title) values (?)", new String[] {"rowid"})) {
                insert.setString(1, "by rowid");
                insert.executeUpdate();
                try (ResultSet keys = insert.getGeneratedKeys()) {
                    assertTrue(keys.next());
                    rowid = keys.getString(1);
                }
            }
            try (PreparedStatement find = connection.prepareStatement(
                    "select title from zl_typed_keys where rowid = chartorowid(?)")) {
                find.setString(1, rowid);
                try (ResultSet row = find.executeQuery()) {
                    assertTrue(row.next(), "no row for " + rowid);
                    assertEquals("by rowid", row.getString(1));
                }
            }
            try (PreparedStatement update = connection.prepareStatement(
                    "update zl_typed_keys set title = ? where title = ?", new String[] {"code"})) {
                update.setString(1, "renamed");
                update.setString(2, "by rowid");
                assertEquals(1, update.executeUpdate());
                try (ResultSet keys = update.getGeneratedKeys()) {
                    assertTrue(keys.next());
                    assertTrue(keys.getString(1).startsWith("K-"), keys.getString(1));
                }
            }
        }
    }
}
