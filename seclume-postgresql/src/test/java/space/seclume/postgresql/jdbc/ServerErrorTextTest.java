package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.postgresql.PgSession;
import space.seclume.tck.fuzz.HostileTransport;

/**
 * A server's ErrorResponse reaches getMessage - and from there every log line
 * the application writes about it. A line break, an escape sequence or a
 * carriage return in it would start a forged log line or repaint a terminal;
 * they arrive escaped, the SQLState as it was sent.
 */
class ServerErrorTextTest {

    private static byte[] message(char type, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(type);
        int length = 4 + body.length;
        out.write((length >> 24) & 0xff);
        out.write((length >> 16) & 0xff);
        out.write((length >> 8) & 0xff);
        out.write(length & 0xff);
        out.writeBytes(body);
        return out.toByteArray();
    }

    private static byte[] errorResponse(String text, String detail) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (String field : new String[] {"SERROR", "VERROR", "C23505", "M" + text, "D" + detail}) {
            body.writeBytes(field.getBytes(StandardCharsets.UTF_8));
            body.write(0);
        }
        body.write(0);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(message('E', body.toByteArray()));
        out.writeBytes(message('Z', new byte[] {'I'}));
        return out.toByteArray();
    }

    private static Map<String, String> parameters() {
        return Map.of("client_encoding", "UTF8", "DateStyle", "ISO, MDY",
                "integer_datetimes", "on", "TimeZone", "UTC", "server_version", "18.0");
    }

    @Test
    void controlCharactersInAnErrorArriveEscaped() throws Exception {
        String text = "duplicate key\n2026-11-27 12:00:00 INFO login ok user=admin\r\u001b[2J";
        PgSession session = PgSession.resume(HostileTransport.of(
                errorResponse(text, "Key (id)=(1)\nexists")), parameters(), 1, 2);
        try (Connection connection = PgConnection.resume(session,
                space.seclume.internal.jdbc.ConnectionFacts.fresh(
                        Connection.TRANSACTION_READ_COMMITTED));
             Statement statement = connection.createStatement()) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> statement.executeUpdate("insert into t values (1)"));
            String said = refused.getMessage();
            assertFalse(said.contains("\n") || said.contains("\r") || said.contains("\u001b"),
                    "a control character reached getMessage: " + said);
            assertTrue(said.contains("duplicate key\\x0a2026-11-27"), said);
            assertTrue(said.contains("\\x1b[2J"), said);
            assertEquals("23505", refused.getSQLState());
        }
    }
}
