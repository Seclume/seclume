package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import org.junit.jupiter.api.Test;

import space.seclume.mysql.jdbc.MyConnection;
import space.seclume.tck.fuzz.HostileTransport;

/**
 * A server's ERR packet reaches getMessage - and every log line written
 * about it. Line breaks, carriage returns and escape sequences in it arrive
 * escaped; the SQLState is the one sent.
 */
class ServerErrorTextTest {

    private static final int CAPABILITIES = 0x0100_0000 | 0x0000_0200 | 0x0000_8000;

    private static byte[] errPacket(String text) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0xff);
        body.write(1062 & 0xff);
        body.write(1062 >> 8);
        body.writeBytes("#23000".getBytes(StandardCharsets.US_ASCII));
        body.writeBytes(text.getBytes(StandardCharsets.UTF_8));
        byte[] payload = body.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(payload.length & 0xff);
        out.write((payload.length >> 8) & 0xff);
        out.write((payload.length >> 16) & 0xff);
        out.write(1);
        out.writeBytes(payload);
        return out.toByteArray();
    }

    @Test
    void controlCharactersInAnErrorArriveEscaped() throws Exception {
        String text = "Duplicate entry '1'\n2026-11-27 12:00:00 INFO login ok user=root\r\u001b[2J";
        MySession session = MySession.resume(HostileTransport.of(errPacket(text)), CAPABILITIES, 7);
        try (Connection connection = MyConnection.resume(session,
                space.seclume.internal.jdbc.ConnectionFacts.fresh(
                        Connection.TRANSACTION_REPEATABLE_READ));
             Statement statement = connection.createStatement()) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> statement.executeUpdate("insert into t values (1)"));
            String said = refused.getMessage();
            assertFalse(said.contains("\n") || said.contains("\r") || said.contains("\u001b"),
                    "a control character reached getMessage: " + said);
            assertTrue(said.contains("'1'\\x0a2026-11-27"), said);
            assertTrue(said.contains("\\x1b[2J"), said);
            assertEquals("23000", refused.getSQLState());
        }
    }
}
