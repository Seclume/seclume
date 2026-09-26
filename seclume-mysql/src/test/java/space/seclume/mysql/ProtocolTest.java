package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.mysql.FakeMySqlServer.Column;
import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;

/**
 * The driver against a server that really speaks MySQL packets.
 *
 * <p>What is checked is what cannot be checked without a server: that the
 * packet framing is right, that the sequence numbers count along, that the
 * login answer is what the server expects, and that text and binary rows are
 * taken apart correctly.
 *
 * <p>The test server recomputes the login answer itself with the JCA. A driver
 * that gets through here has formed it correctly - not merely wrong in a
 * consistent way.
 */
class ProtocolTest {

    private static final String USER = "seclume_test";
    private static final String PASSWORD = "ein Testpasswort äöü";

    /** In the test too the password only goes into the driver off-heap. */
    private static SecretProvider secret() {
        byte[] bytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        return new CallbackSecretProvider(256, target -> {
            for (int i = 0; i < bytes.length; i++) {
                target.set(ValueLayout.JAVA_BYTE, i, bytes[i]);
            }
            return bytes.length;
        });
    }

    private static MySession.Settings settings(FakeMySqlServer server) {
        return new MySession.Settings("127.0.0.1", server.port(), "testdb", USER, secret());
    }

    @Test
    void handshakeAndTextQuery() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            server.answerWith(
                    List.of(new Column("id", MyTypes.LONGLONG), new Column("label", MyTypes.VAR_STRING)),
                    List.of(List.of("1", "eins"), List.of("2", "zwei")));
            server.start();

            try (MySession session = MySession.open(settings(server))) {
                assertEquals("8.4.0-fake", session.serverVersion());
                assertEquals("mysql_native_password", session.authenticationPlugin());
                assertEquals(42, session.connectionId());

                List<String> values = new ArrayList<>();
                session.query("select id, label from t", row -> {
                    values.add(String.valueOf(row.getLong(0)));
                    values.add(row.getString(1));
                });
                assertEquals(List.of("1", "eins", "2", "zwei"), values);
            }
            server.rethrowFailure();
            assertEquals(List.of("select id, label from t"), server.received());
        }
    }

    /** A wrong password does not get past the test server. */
    @Test
    void aWrongPasswordIsRejected() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, "das richtige Passwort")) {
            server.start();
            assertThrows(Exception.class,
                    () -> MySession.open(settings(server)).close());
        }
    }

    @Test
    void readsNullAndUnicode() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            server.answerWith(
                    List.of(new Column("a", MyTypes.VAR_STRING), new Column("b", MyTypes.VAR_STRING)),
                    java.util.Collections.singletonList(
                            java.util.Arrays.asList(null, "mit Umlaut äöü und 🔐")));
            server.start();

            try (MySession session = MySession.open(settings(server))) {
                List<String> values = new ArrayList<>();
                session.query("select a, b from t", row -> {
                    values.add(row.isNull(0) ? "<null>" : row.getString(0));
                    values.add(row.getString(1));
                });
                assertEquals(List.of("<null>", "mit Umlaut äöü und 🔐"), values);
            }
            server.rethrowFailure();
        }
    }

    @Test
    void serverErrorsCarryNumberAndSqlState() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            server.failWith("You have an error in your SQL syntax");
            server.start();

            try (MySession session = MySession.open(settings(server))) {
                // A syntax error is the JDBC 4 type for its state class, as
                // Connector/J raises it; the number stays the server's.
                java.sql.SQLSyntaxErrorException failure = assertThrows(
                        java.sql.SQLSyntaxErrorException.class, () -> session.execute("selct 1"));
                assertEquals(1064, failure.getErrorCode());
                assertEquals("42000", failure.getSQLState());
                assertTrue(failure.getMessage().contains("error in your SQL syntax"));
            }
            server.rethrowFailure();
        }
    }

    /** The binary protocol: numbers as eight bytes, NULL in the bitmask. */
    @Test
    void preparedStatementsReadBinaryRows() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            server.answerWith(
                    List.of(new Column("n", MyTypes.LONGLONG), new Column("s", MyTypes.VAR_STRING)),
                    java.util.Arrays.asList(
                            java.util.Arrays.asList("-4711", "Text"),
                            java.util.Arrays.asList("9223372036854775807", null)));
            server.start();

            try (MySession session = MySession.open(settings(server))) {
                MySession.Prepared prepared = session.prepare("select n, s from t where x = ?");
                assertEquals(1, prepared.parameterCount());
                assertEquals(2, prepared.fields().size());

                MyParameters parameters = new MyParameters(1);
                parameters.set(1, "egal");
                List<String> values = new ArrayList<>();
                session.executePrepared(prepared, parameters, row -> {
                    values.add(String.valueOf(row.getLong(0)));
                    values.add(row.isNull(1) ? "<null>" : row.getString(1));
                });
                assertEquals(List.of("-4711", "Text", "9223372036854775807", "<null>"), values);
                session.closeStatement(prepared.statementId());
            }
            server.rethrowFailure();
        }
    }

    @Test
    void pingAndResetGoThroughTheSameFraming() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            server.start();
            try (MySession session = MySession.open(settings(server))) {
                session.ping();
                session.resetConnection();
                session.ping();
            }
            server.rethrowFailure();
        }
    }

    // ---- through the JDBC surface ----------------------------------------

    @Test
    void theDriverManagerSpeaksToTheServer() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            server.answerWith(
                    List.of(new Column("id", MyTypes.LONGLONG, MyTypes.FLAG_NOT_NULL, 20),
                            new Column("label", MyTypes.VAR_STRING, 0, 80)),
                    List.of(List.of("7", "sieben")));
            server.start();

            java.util.Properties properties = new java.util.Properties();
            properties.setProperty("user", USER);
            properties.setProperty("provider", "callback");
            // The path through the URL needs a file; this is about the JDBC
            // layer, so the provider goes in directly via the DataSource.
            space.seclume.mysql.jdbc.MyDataSource dataSource =
                    new space.seclume.mysql.jdbc.MyDataSource();
            dataSource.setHost("127.0.0.1");
            dataSource.setPort(server.port());
            dataSource.setDatabase("testdb");
            dataSource.setUser(USER);
            dataSource.setSecretProvider(secret());

            try (Connection connection = dataSource.getConnection();
                 Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("select id, label from t")) {
                ResultSetMetaData meta = result.getMetaData();
                assertEquals(2, meta.getColumnCount());
                assertEquals("id", meta.getColumnLabel(1));
                assertEquals(Types.BIGINT, meta.getColumnType(1));
                assertEquals(ResultSetMetaData.columnNoNulls, meta.isNullable(1));
                assertEquals(Types.VARCHAR, meta.getColumnType(2));
                // 80 bytes of utf8mb4 are 20 characters.
                assertEquals(20, meta.getPrecision(2));

                assertTrue(result.next());
                assertEquals(7L, result.getLong("id"));
                assertEquals("sieben", result.getString(2));
                assertFalse(result.next());
            }
            server.rethrowFailure();
        }
    }

    @Test
    void preparedStatementsThroughJdbc() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            server.answerWith(
                    List.of(new Column("n", MyTypes.LONGLONG), new Column("s", MyTypes.VAR_STRING)),
                    java.util.Arrays.asList(java.util.Arrays.asList("123", null)));
            server.start();

            space.seclume.mysql.jdbc.MyDataSource dataSource =
                    new space.seclume.mysql.jdbc.MyDataSource();
            dataSource.setHost("127.0.0.1");
            dataSource.setPort(server.port());
            dataSource.setDatabase("testdb");
            dataSource.setUser(USER);
            dataSource.setSecretProvider(secret());

            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement(
                         "select n, s from t where x = ?")) {
                statement.setString(1, "wert");
                try (ResultSet result = statement.executeQuery()) {
                    assertTrue(result.next());
                    assertEquals(123, result.getInt("n"));
                    assertEquals(123L, result.getObject("n"));
                    assertNull(result.getString("s"));
                    assertTrue(result.wasNull());
                }
            }
            server.rethrowFailure();
            assertEquals(List.of("select n, s from t where x = ?"), server.received());
        }
    }

    /** A {@code password=} in the URL is refused - with a reason. */
    @Test
    void aPasswordInTheUrlIsRefused() {
        SQLException failure = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(
                        "jdbc:seclume:mysql://127.0.0.1:3306/db?user=x&password=geheim"));
        assertTrue(failure.getMessage().contains("not a seclume setting"),
                "expected the refusal to explain itself, got: " + failure.getMessage());
    }

    @Test
    void theDriverAcceptsItsOwnUrlsAndNoOthers() throws Exception {
        java.sql.Driver driver = new space.seclume.mysql.jdbc.MyDriver();
        assertTrue(driver.acceptsURL("jdbc:seclume:mysql://localhost/db"));
        assertTrue(driver.acceptsURL("jdbc:seclume:mariadb://localhost/db"));
        assertFalse(driver.acceptsURL("jdbc:mysql://localhost/db"));
        assertFalse(driver.acceptsURL("jdbc:seclume:postgresql://localhost/db"));
        assertNull(driver.connect("jdbc:mysql://localhost/db", null));
    }
}
