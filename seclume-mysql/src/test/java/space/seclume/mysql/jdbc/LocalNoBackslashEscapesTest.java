package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Under a session's NO_BACKSLASH_ESCAPES a backslash in a literal is itself.
 * The catalog queries doubled it anyway - a column called {@code a\b} was
 * looked for as {@code a\\b} and not found - and the JDBC escape translation
 * took a literal ending in a backslash for one that went on.
 */
class LocalNoBackslashEscapesTest {

    private static final String HOST = System.getProperty("seclume.mysql.host",
            space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mysql.port", 3307);

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
        url = "jdbc:seclume:mysql://" + HOST + ":" + PORT + "/seclume_test?tls=prefer&user=seclume_test"
                + "&allowPublicKeyRetrieval=true&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    @Test
    void aNameWithABackslashIsFoundAndEscapesAreTranslated() throws Exception {
        String table = "nbe_" + UUID.randomUUID().toString().substring(0, 8);
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement()) {
            s.execute("create table " + table + " (`a\\b` int, ab int)");
            try {
                s.execute("set session sql_mode = concat(@@sql_mode, ',NO_BACKSLASH_ESCAPES')");
                // A JDBC pattern escapes with a backslash: a\\b is the column a\b.
                try (ResultSet columns = c.getMetaData().getColumns(null, null, table, "a\\\\b")) {
                    assertTrue(columns.next(), "the column a\\b was not found");
                    assertEquals("a\\b", columns.getString("COLUMN_NAME"));
                    assertFalse(columns.next());
                }
                // 'x\' ends at its quote here; the escape clause after it is SQL.
                try (ResultSet row = s.executeQuery(
                        "select 'x\\', 'a_b' like 'a!_b' {escape '!'}")) {
                    assertTrue(row.next());
                    assertEquals("x\\", row.getString(1));
                    assertEquals(1, row.getInt(2));
                }
            } finally {
                s.execute("drop table if exists " + table);
            }
        }
    }
}
