package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.tck.fuzz.HostileTransport;

/**
 * A DataRow has as many values as its RowDescription has columns. With one
 * too few, the session took the missing cell's place and length from the row
 * before - offsets into the same receive buffer - and handed another row's
 * value on as this one's. A server, or anything between it and the client,
 * that sends such a row now breaks the connection instead.
 */
class RowColumnCountTest {

    private static void int16(ByteArrayOutputStream out, int value) {
        out.write((value >> 8) & 0xff);
        out.write(value & 0xff);
    }

    private static void int32(ByteArrayOutputStream out, int value) {
        out.write((value >> 24) & 0xff);
        out.write((value >> 16) & 0xff);
        out.write((value >> 8) & 0xff);
        out.write(value & 0xff);
    }

    private static byte[] message(char type, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(type);
        int32(out, 4 + body.length);
        out.writeBytes(body);
        return out.toByteArray();
    }

    private static byte[] description(String... names) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int16(body, names.length);
        for (String name : names) {
            body.writeBytes(name.getBytes(StandardCharsets.UTF_8));
            body.write(0);
            int32(body, 0);
            int16(body, 0);
            int32(body, 25);                              // text
            int16(body, -1);
            int32(body, -1);
            int16(body, 0);
        }
        return message('T', body.toByteArray());
    }

    private static byte[] row(String... values) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int16(body, values.length);
        for (String value : values) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            int32(body, bytes.length);
            body.writeBytes(bytes);
        }
        return message('D', body.toByteArray());
    }

    private static byte[] answer(byte[]... messages) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] message : messages) {
            out.writeBytes(message);
        }
        out.writeBytes(message('C', "SELECT 2\0".getBytes(StandardCharsets.UTF_8)));
        out.writeBytes(message('Z', new byte[] {'I'}));
        return out.toByteArray();
    }

    private static Map<String, String> parameters() {
        return Map.of("client_encoding", "UTF8", "DateStyle", "ISO, MDY",
                "integer_datetimes", "on", "TimeZone", "UTC", "server_version", "18.0");
    }

    /** Every row's values as text, as a RowHandler sees them. */
    private static List<List<String>> rows(PgSession session) throws SQLException {
        List<List<String>> rows = new ArrayList<>();
        session.simpleQuery("select owner, secret from t", row -> {
            List<String> values = new ArrayList<>();
            for (int i = 0; i < row.fields().size(); i++) {
                values.add(row.getString(i));
            }
            rows.add(values);
        });
        return rows;
    }

    @Test
    void rowsOfTheRightWidthAreRead() throws SQLException {
        PgSession session = PgSession.resume(HostileTransport.of(answer(
                description("owner", "secret"), row("alice", "a-1"), row("bob", "b-2"))),
                parameters(), 1, 2);
        assertEquals(List.of(List.of("alice", "a-1"), List.of("bob", "b-2")), rows(session));
        assertTrue(session.isOpen());
    }

    @Test
    void aRowWithAValueTooFewIsRefusedNotFilledFromTheRowBefore() {
        PgSession session = PgSession.resume(HostileTransport.of(answer(
                description("owner", "secret"), row("alice", "alices-secret"), row("bob"))),
                parameters(), 1, 2);
        List<List<String>> seen = new ArrayList<>();
        SQLException refused = assertThrows(SQLException.class, () -> seen.addAll(rows(session)));
        assertTrue(refused.getMessage().contains("a row of 1 values in a result of 2 columns")
                || String.valueOf(refused.getCause()).contains("a row of 1 values"),
                refused.toString());
        assertFalse(seen.stream().anyMatch(r -> r.contains("bob")),
                "bob's row was handed on with alice's secret in it");
        assertFalse(session.isOpen(), "a stream at an unknown place is not used again");
    }

    @Test
    void aRowWithAValueTooManyIsRefused() {
        PgSession session = PgSession.resume(HostileTransport.of(answer(
                description("owner"), row("alice", "extra"))), parameters(), 1, 2);
        assertThrows(SQLException.class, () -> rows(session));
        assertFalse(session.isOpen());
    }
}
