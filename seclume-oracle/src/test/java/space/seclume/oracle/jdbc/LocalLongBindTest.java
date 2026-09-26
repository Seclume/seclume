package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Types;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Values too long for a VARCHAR2 or RAW bind, with other binds behind them.
 *
 * <p>The server takes such a bind for a {@code LONG} and reads its value last,
 * whatever its place in the statement. The driver wrote it in place, and the
 * value behind it was read as the long one's: ORA-01461, naming a position
 * one too far. A long value as the last bind worked, which is why every test
 * before this one passed - Hibernate's insert, with its LOB columns in
 * alphabetical order and nulls after the large ones, did not.
 */
@Timeout(120)
class LocalLongBindTest {

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

    @Test
    void longValuesBeforeOtherBindsArrive() throws Exception {
        String text = "Zeile mit Umlauten äöü\n".repeat(30_000);
        byte[] bytes = new byte[700_000]; // seclume-allow: test payload, not a secret
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (i * 31 + 7);
        }
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            recreate(statement);
            String insert = "insert into zl_long_bind (title, body, data, picture, script, words) "
                    + "values (?, ?, ?, ?, ?, ?)";
            try (PreparedStatement row = connection.prepareStatement(insert, new String[] {"id"})) {
                row.setString(1, "both");
                row.setString(2, text);
                row.setBytes(3, bytes);
                row.setNull(4, Types.BLOB);
                row.setNull(5, Types.CLOB);
                row.setInt(6, 7);
                assertEquals(1, row.executeUpdate());
                try (ResultSet keys = row.getGeneratedKeys()) {
                    keys.next();
                    assertEquals(1, keys.getLong(1));
                }
            }
            try (ResultSet back = statement.executeQuery(
                    "select title, body, data, words from zl_long_bind where id = 1")) {
                back.next();
                assertEquals("both", back.getString(1));
                assertEquals(text, back.getString(2));
                assertArrayEquals(bytes, back.getBytes(3));
                assertEquals(7, back.getInt(4));
            }
            statement.execute("drop table zl_long_bind purge");
        }
    }

    /** A batch describes its variables by the widest row - and orders by that. */
    @Test
    void aBatchWithOneLongRowKeepsEveryRowInStep() throws Exception {
        String longText = "x".repeat(50_000);
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            recreate(statement);
            try (PreparedStatement rows = connection.prepareStatement(
                    "insert into zl_long_bind (title, body, words) values (?, ?, ?)")) {
                for (int i = 0; i < 3; i++) {
                    rows.setString(1, "row " + i);
                    rows.setString(2, i == 1 ? longText : "short " + i);
                    rows.setInt(3, i);
                    rows.addBatch();
                }
                rows.executeBatch();
            }
            try (ResultSet back = statement.executeQuery(
                    "select title, body, words from zl_long_bind order by words")) {
                for (int i = 0; i < 3; i++) {
                    back.next();
                    assertEquals("row " + i, back.getString(1));
                    assertEquals(i == 1 ? longText : "short " + i, back.getString(2));
                    assertEquals(i, back.getInt(3));
                }
            }
            statement.execute("drop table zl_long_bind purge");
        }
    }

    private static void recreate(Statement statement) throws Exception {
        statement.execute("begin execute immediate 'drop table zl_long_bind purge'; "
                + "exception when others then null; end;");
        statement.execute("create table zl_long_bind (id number(19) generated by default "
                + "as identity primary key, title varchar2(80 char), body clob, data blob, "
                + "picture blob, script clob, words number(10))");
    }
}
