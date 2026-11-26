package space.seclume.sqlserver.tds;

import static space.seclume.sqlserver.tds.TdsDecoderFuzzTest.END_OF_MESSAGE;
import static space.seclume.sqlserver.tds.TdsDecoderFuzzTest.done;
import static space.seclume.sqlserver.tds.TdsDecoderFuzzTest.intColumn;
import static space.seclume.sqlserver.tds.TdsDecoderFuzzTest.intRow;
import static space.seclume.sqlserver.tds.TdsDecoderFuzzTest.join;
import static space.seclume.sqlserver.tds.TdsDecoderFuzzTest.nullRow;
import static space.seclume.sqlserver.tds.TdsDecoderFuzzTest.packet;
import static space.seclume.sqlserver.tds.TdsDecoderFuzzTest.textColumn;
import static space.seclume.sqlserver.tds.TdsDecoderFuzzTest.textRow;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.sqlserver.jdbc.TdsConnection;
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
class TdsGetterFuzzTest {

    private static byte[] text(String value) {
        return packet(END_OF_MESSAGE, join(textColumn(), textRow(value), done(1)));
    }

    static Map<String, byte[]> seeds() {
        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("an integer", packet(END_OF_MESSAGE, join(intColumn(), intRow(7), done(1))));
        seeds.put("a null", packet(END_OF_MESSAGE, join(intColumn(), nullRow(), done(1))));
        seeds.put("a number as text", text("12345.678"));
        seeds.put("a date as text", text("2026-11-26 07:59:59.1234567"));
        seeds.put("a uuid as text", text("123e4567-e89b-12d3-a456-426614174000"));
        seeds.put("a boolean as text", text("1"));
        // Text a converter does not take, each where it meets one.
        seeds.put("not a number", text("12x"));
        seeds.put("beyond a long", text("99999999999999999999999"));
        seeds.put("a huge exponent", text("1e999999999"));
        seeds.put("out of calendar", text("2026-13-45"));
        seeds.put("out of clock", text("25:61:61"));
        seeds.put("a short uuid", text("123e4567"));
        seeds.put("empty", text(""));
        return seeds;
    }

    private static Connection connection(byte[] script) {
        TdsSession session = TdsSession.resume(HostileTransport.of(script),
                4096, "master", "seclume", 16);
        return TdsConnection.resume(session, space.seclume.internal.jdbc.ConnectionFacts.fresh(
                Connection.TRANSACTION_READ_COMMITTED));
    }

    /** The seeds reach a row: whether the getters take its value is the sweep's question. */
    @Test
    void theSeedsReachTheGetters() throws Exception {
        for (Map.Entry<String, byte[]> seed : seeds().entrySet()) {
            try (Connection connection = connection(seed.getValue());
                 Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select n from t")) {
                org.junit.jupiter.api.Assertions.assertTrue(rows.next(), seed.getKey());
            }
        }
    }

    @Test
    void everyGetterSurvivesAHostileValue() {
        SessionContract.sweep("SQL Server getters", seeds(), script -> {
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
}
