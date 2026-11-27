package space.seclume.mysql;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.mysql.jdbc.MyConnection;
import space.seclume.tck.fuzz.GetterSweep;
import space.seclume.tck.fuzz.HostileTransport;
import space.seclume.tck.fuzz.SessionContract;

/**
 * The decoders' fuzz test reads one value as a string. Every getter on every
 * column of a mutated answer - and on text a converter does not take, read
 * as a number, a date, a UUID - may refuse with an SQLException and with
 * nothing else.
 */
@Timeout(1200)
class MyGetterFuzzTest {

    /** {@code CLIENT_DEPRECATE_EOF} plus the flags a modern session negotiates. */
    private static final int CAPABILITIES = 0x0100_0000 | 0x0000_0200 | 0x0000_8000;

    private static byte[] packet(int sequence, byte[] payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(payload.length & 0xff);
        out.write((payload.length >> 8) & 0xff);
        out.write((payload.length >> 16) & 0xff);
        out.write(sequence & 0xff);
        out.writeBytes(payload);
        return out.toByteArray();
    }

    private static byte[] join(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    private static void lenenc(ByteArrayOutputStream out, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.write(bytes.length);
        out.writeBytes(bytes);
    }

    private static byte[] column(int type) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (String part : new String[] {"def", "seclume_test", "t", "t", "n", "n"}) {
            lenenc(body, part);
        }
        body.write(0x0c);
        body.writeBytes(new byte[] {0x21, 0x00});           // character set: utf8
        body.writeBytes(new byte[] {0x00, 0x01, 0x00, 0x00}); // column length
        body.write(type);
        body.writeBytes(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00});
        return packet(2, body.toByteArray());
    }

    private static byte[] answer(int type, String value) {
        byte[] row;
        if (value == null) {
            row = packet(3, new byte[] {(byte) 0xfb});
        } else {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            lenenc(body, value);
            row = packet(3, body.toByteArray());
        }
        return join(packet(1, new byte[] {0x01}), column(type), row,
                // CLIENT_DEPRECATE_EOF: the rows end with an OK packet headed 0xfe
                packet(4, new byte[] {(byte) 0xfe, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}));
    }

    private static byte[] text(String value) {
        return answer(0x0f, value);                         // MYSQL_TYPE_VARCHAR
    }

    static Map<String, byte[]> seeds() {
        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("an integer", answer(0x03, "7"));         // MYSQL_TYPE_LONG
        seeds.put("a null", answer(0x03, null));
        seeds.put("a decimal", answer(0xf6, "12345.678"));  // MYSQL_TYPE_NEWDECIMAL
        seeds.put("a datetime", answer(0x0c, "2026-11-26 07:59:59.123456"));
        seeds.put("a date", answer(0x0a, "2026-11-26"));
        seeds.put("a time", answer(0x0b, "-838:59:59"));
        seeds.put("a uuid as text", text("123e4567-e89b-12d3-a456-426614174000"));
        seeds.put("a boolean as text", text("1"));
        seeds.put("not a number", text("12x"));
        seeds.put("beyond a long", answer(0x08, "99999999999999999999999"));
        seeds.put("a huge exponent", answer(0x05, "1e999999999"));
        seeds.put("out of calendar", answer(0x0a, "2026-13-45"));
        seeds.put("a zero date", answer(0x0c, "0000-00-00 00:00:00"));
        seeds.put("out of clock", answer(0x0b, "25:61:61"));
        seeds.put("a short uuid", text("123e4567"));
        seeds.put("empty", text(""));
        return seeds;
    }

    private static Connection connection(byte[] script) {
        MySession session = MySession.resume(HostileTransport.of(script), CAPABILITIES, 7);
        return MyConnection.resume(session, space.seclume.internal.jdbc.ConnectionFacts.fresh(
                Connection.TRANSACTION_REPEATABLE_READ));
    }

    /** The seeds reach a row: whether the getters take its value is the sweep's question. */
    @Test
    void theSeedsReachTheGetters() throws Exception {
        for (Map.Entry<String, byte[]> seed : seeds().entrySet()) {
            try (Connection connection = connection(seed.getValue());
                 Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select n from t")) {
                org.junit.jupiter.api.Assertions.assertTrue(rows.next(), seed.getKey());
            } catch (java.sql.SQLException e) {
                throw new AssertionError(seed.getKey() + " did not reach a row", e);
            }
        }
    }

    @Test
    void everyGetterSurvivesAHostileValue() {
        SessionContract.sweep("MySQL getters", seeds(), script -> {
            Connection connection = connection(script);
            return new SessionContract.Driven(
                    () -> GetterSweep.readEverything(connection, "select n from t"),
                    () -> {
                        try {
                            return !connection.isClosed();
                        } catch (java.sql.SQLException e) {
                            return false;
                        }
                    },
                    connection);
        });
    }

    /** The same contract, with Jazzer choosing the answers. */
    @com.code_intelligence.jazzer.junit.FuzzTest(maxDuration = "60s")
    void coverageGuided(byte[] script) {
        Connection connection = connection(script);
        SessionContract.require(new SessionContract.Driven(
                () -> GetterSweep.readEverything(connection, "select n from t"),
                () -> {
                    try {
                        return !connection.isClosed();
                    } catch (java.sql.SQLException e) {
                        return false;
                    }
                },
                connection));
    }
}
