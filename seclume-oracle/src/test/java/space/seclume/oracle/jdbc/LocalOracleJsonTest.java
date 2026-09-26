package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Oracle's native JSON type, read back as JSON text.
 *
 * <p>A JSON column arrives as a LOB locator - a temporary one, 38 bytes and
 * not the 112 of a CLOB - and what it holds is OSON, a binary tree. The row
 * reader looked for the CLOB's descriptor, read the locator as a short value
 * and the rest of the row as the next columns: the connection broke on the
 * first JSON column anyone selected. Hibernate's JSON mapping found it.
 *
 * <p>The server is its own reference here: every document is compared with
 * what {@code json_serialize} makes of the same column.
 */
@Timeout(120)
class LocalOracleJsonTest {

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

    /** Documents that reach each corner of the format. */
    private static final List<String> DOCUMENTS = List.of(
            "{\"a\":1,\"b\":\"xy\"}",
            "{}",
            "[]",
            "[1,2.5,-3,0,-0.001,12345678901234567890123456789,1e-30,true,false,null]",
            "{\"nested\":{\"deeper\":{\"list\":[{\"x\":1},{\"x\":2,\"y\":[]}]}}}",
            "{\"quote\":\"a \\\"b\\\" c\",\"slash\":\"a\\\\b\",\"tab\":\"a\\tb\\nc\"}",
            "{\"umlaut\":\"Grüße, 東京 😀\"}",
            "\"a scalar string\"",
            "42",
            "[{\"id\":1,\"name\":\"a\"},{\"id\":2,\"name\":\"b\"},{\"id\":3,\"name\":\"c\"}]");

    @Test
    void everyDocumentReadsAsTheServerSerializesIt() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            recreate(statement);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_json values (?, json(?))")) {
                for (int i = 0; i < DOCUMENTS.size(); i++) {
                    insert.setInt(1, i);
                    insert.setString(2, DOCUMENTS.get(i));
                    insert.executeUpdate();
                }
                insert.setInt(1, 100);
                insert.setString(2, wide());
                insert.executeUpdate();
            }
            // Built on the server: a value this long cannot be bound as the
            // argument of json() - past 32 KB a string is a LONG, and a LONG
            // is no function's argument. ojdbc has the same limit.
            statement.executeUpdate("insert into zl_json select 101, json_arrayagg("
                    + "json_object('k' value rpad('v', 300 + level, 'v'), 'i' value level) "
                    + "order by level returning json) from dual connect by level <= 300");
            statement.executeUpdate("insert into zl_json values (104, json_object("
                    + "'w' value rpad(to_clob('w'), 70000, 'w') returning json))");
            statement.executeUpdate("insert into zl_json values (102, null)");
            statement.executeUpdate("insert into zl_json values (103, json_object("
                    + "'day' value date '2024-02-29', "
                    + "'at' value timestamp '2024-02-29 13:14:15.123456', "
                    + "'bin' value hextoraw('00FF10') returning json))");
            try (ResultSet rows = statement.executeQuery("select id, j, "
                    + "json_serialize(j returning clob) from zl_json order by id")) {
                int seen = 0;
                while (rows.next()) {
                    String expected = rows.getString(3);
                    String actual = rows.getString(2);
                    if (expected == null) {
                        assertNull(actual, "row " + rows.getInt(1));
                    } else {
                        assertEquals(expected, actual, "row " + rows.getInt(1));
                    }
                    seen++;
                }
                assertEquals(DOCUMENTS.size() + 5, seen);
            }
        }
    }

    /** Small fetches, so that rows with a JSON column are carried across blocks. */
    @Test
    void jsonColumnsKeepTheRowInStepAcrossFetches() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            recreate(statement);
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into zl_json values (?, json(?))")) {
                for (int i = 0; i < 25; i++) {
                    insert.setInt(1, i);
                    insert.setString(2, "{\"n\":" + i + "}");
                    insert.executeUpdate();
                }
            }
            statement.setFetchSize(4);
            try (ResultSet rows = statement.executeQuery(
                    "select id, j, 'after' from zl_json order by id")) {
                for (int i = 0; i < 25; i++) {
                    assertTrue(rows.next());
                    assertEquals(i, rows.getInt(1));
                    assertEquals("{\"n\":" + i + "}", rows.getString(2));
                    assertEquals("after", rows.getString(3));
                }
                assertFalse(rows.next());
            }
            try (ResultSet rows = statement.executeQuery("select j from zl_json where id = 7")) {
                rows.next();
                assertEquals("JSON", rows.getMetaData().getColumnTypeName(1));
                assertEquals("{\"n\":7}", rows.getObject(1));
                assertEquals("{\"n\":7}", new String(rows.getBytes(1), StandardCharsets.UTF_8));
            }
        }
    }

    /** More than 255 distinct field names, so a field id takes two bytes. */
    private static String wide() {
        StringBuilder text = new StringBuilder("{");
        for (int i = 0; i < 400; i++) {
            text.append(i == 0 ? "" : ",").append("\"field").append(i).append("\":").append(i);
        }
        return text.append('}').toString();
    }

    private static void recreate(Statement statement) throws Exception {
        statement.execute("begin execute immediate 'drop table zl_json purge'; "
                + "exception when others then null; end;");
        statement.execute("create table zl_json (id number, j json)");
    }
}
