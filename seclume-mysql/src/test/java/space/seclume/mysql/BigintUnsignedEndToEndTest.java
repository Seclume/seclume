package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.ValueLayout;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.mysql.FakeMySqlServer.Column;
import space.seclume.mysql.jdbc.MyConnection;
import space.seclume.secret.CallbackSecretProvider;

/**
 * The BIGINT UNSIGNED fix, through JDBC as an application meets it: a value
 * above Long.MAX_VALUE came back from getLong negative or wrapped - 2^64-1 as
 * -1. Over the text protocol and the binary one, from a server that really
 * speaks MySQL packets, getLong refuses with 22003 and the exact value is
 * there for getBigDecimal and getString.
 */
class BigintUnsignedEndToEndTest {

    private static final String USER = "seclume_test";
    private static final String PASSWORD = "ein Testpasswort";
    private static final Column UNSIGNED =
            new Column("v", MyTypes.LONGLONG, MyTypes.FLAG_UNSIGNED, 20);

    private static Connection connect(FakeMySqlServer server) throws SQLException {
        byte[] bytes = PASSWORD.getBytes(StandardCharsets.UTF_8); // seclume-allow: a test password
        MySession session = MySession.open(new MySession.Settings("127.0.0.1", server.port(),
                "testdb", USER, new CallbackSecretProvider(64, target -> {
                    for (int i = 0; i < bytes.length; i++) {
                        target.set(ValueLayout.JAVA_BYTE, i, bytes[i]);
                    }
                    return bytes.length;
                })).allowingLegacyHash());   // the stand-in: native, no TLS
        return MyConnection.resume(session, space.seclume.internal.jdbc.ConnectionFacts.fresh(
                Connection.TRANSACTION_REPEATABLE_READ));
    }

    private static void refusesLongButKeepsTheValue(ResultSet rows, String exact)
            throws SQLException {
        assertTrue(rows.next());
        SQLException refused = assertThrows(SQLException.class, () -> rows.getLong(1));
        assertEquals("22003", refused.getSQLState(), refused.getMessage());
        assertEquals(new BigDecimal(exact), rows.getBigDecimal(1));
        assertEquals(exact, rows.getString(1));
    }

    @Test
    void theTextProtocolRefusesWhatNoLongHolds() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            server.answerWith(List.of(UNSIGNED), List.of(List.of("18446744073709551621")));
            server.start();
            try (Connection connection = connect(server);
                 Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select v from t")) {
                refusesLongButKeepsTheValue(rows, "18446744073709551621");
            }
            server.rethrowFailure();
        }
    }

    @Test
    void theBinaryProtocolRefusesWhatNoLongHolds() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            // Eight bytes of ones: 2^64-1 unsigned, -1 to a signed reading.
            server.answerWith(List.of(UNSIGNED), List.of(List.of("-1")));
            server.start();
            try (Connection connection = connect(server);
                 PreparedStatement statement = connection.prepareStatement(
                         "select v from t where x = ?")) {
                statement.setString(1, "x");
                try (ResultSet rows = statement.executeQuery()) {
                    refusesLongButKeepsTheValue(rows, "18446744073709551615");
                }
            }
            server.rethrowFailure();
        }
    }
}
