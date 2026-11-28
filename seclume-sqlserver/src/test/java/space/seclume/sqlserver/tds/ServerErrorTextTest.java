package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static space.seclume.sqlserver.tds.TdsDecoderFuzzTest.END_OF_MESSAGE;
import static space.seclume.sqlserver.tds.TdsDecoderFuzzTest.done;
import static space.seclume.sqlserver.tds.TdsDecoderFuzzTest.join;
import static space.seclume.sqlserver.tds.TdsDecoderFuzzTest.packet;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import org.junit.jupiter.api.Test;

import space.seclume.sqlserver.jdbc.TdsConnection;
import space.seclume.tck.fuzz.HostileTransport;

/**
 * A server's ERROR token reaches getMessage - and every log line written
 * about it. Line breaks, carriage returns and escape sequences in it arrive
 * escaped.
 */
class ServerErrorTextTest {

    private static void u16(ByteArrayOutputStream out, int value) {
        out.write(value & 0xff);
        out.write((value >> 8) & 0xff);
    }

    private static void u32(ByteArrayOutputStream out, int value) {
        u16(out, value & 0xffff);
        u16(out, value >>> 16);
    }

    private static byte[] error(String message) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        u32(body, 2627);                                  // a primary key violation
        body.write(1);                                    // state
        body.write(14);                                   // severity
        byte[] text = message.getBytes(StandardCharsets.UTF_16LE);
        u16(body, text.length / 2);
        body.writeBytes(text);
        byte[] server = "fake".getBytes(StandardCharsets.UTF_16LE);
        body.write(server.length / 2);
        body.writeBytes(server);
        body.write(0);                                    // no procedure
        u32(body, 1);                                     // line
        ByteArrayOutputStream token = new ByteArrayOutputStream();
        token.write(Tds.TOKEN_ERROR);
        u16(token, body.size());
        token.writeBytes(body.toByteArray());
        return token.toByteArray();
    }

    @Test
    void controlCharactersInAnErrorArriveEscaped() throws Exception {
        String text = "Violation of PRIMARY KEY\n2026-11-27 12:00:00 INFO login ok user=sa\r\u001b[2J";
        byte[] script = packet(END_OF_MESSAGE, join(error(text), done(0)));
        TdsSession session = TdsSession.resume(HostileTransport.of(script), 4096, "master",
                "seclume", 16);
        try (Connection connection = TdsConnection.resume(session,
                space.seclume.internal.jdbc.ConnectionFacts.fresh(
                        Connection.TRANSACTION_READ_COMMITTED));
             Statement statement = connection.createStatement()) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> statement.executeUpdate("insert into t values (1)"));
            String said = refused.getMessage();
            assertFalse(said.contains("\n") || said.contains("\r") || said.contains("\u001b"),
                    "a control character reached getMessage: " + said);
            assertTrue(said.contains("KEY\\x0a2026-11-27"), said);
            assertTrue(said.contains("\\x1b[2J"), said);
        }
    }
}
