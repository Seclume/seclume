package space.seclume.postgresql.jdbc;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.postgresql.PgSession;
import space.seclume.tck.fuzz.HostileTransport;
import space.seclume.tck.fuzz.SessionContract;

/**
 * The decoders' fuzz test stops at the first value: askOneValue reads a
 * string. Behind a ResultSet sit the converters - getLong of a text that is
 * no number, getTimestamp of a date that is no date, getBigDecimal of an
 * exponent with a thousand digits, getBytes of a bytea escape cut in half -
 * and each of those met the server's bytes untried. Every getter, on every
 * column of every row of a hostile answer, may refuse with an SQLException
 * and nothing else: no NumberFormatException, no DateTimeException, no
 * index out of bounds, no hang.
 */
@Timeout(1200)
class PgGetterFuzzTest {

    private static byte[] message(char type, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(type);
        int32(out, 4 + body.length);
        out.writeBytes(body);
        return out.toByteArray();
    }

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

    private static byte[] join(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    /** One text-format column of {@code typeOid}. */
    private static byte[] rowDescription(int typeOid) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int16(body, 1);
        body.writeBytes("v\0".getBytes(StandardCharsets.UTF_8));
        int32(body, 0);
        int16(body, 0);
        int32(body, typeOid);
        int16(body, -1);
        int32(body, -1);
        int16(body, 0);
        return message('T', body.toByteArray());
    }

    private static byte[] dataRow(String value) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int16(body, 1);
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        int32(body, bytes.length);
        body.writeBytes(bytes);
        return message('D', body.toByteArray());
    }

    private static byte[] answer(int typeOid, String value) {
        return join(rowDescription(typeOid), dataRow(value),
                message('C', "SELECT 1\0".getBytes(StandardCharsets.UTF_8)),
                message('Z', new byte[] {'I'}));
    }

    /** One seed per converter worth spoiling, each a value it takes. */
    static Map<String, byte[]> seeds() {
        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("int4", answer(23, "2147483647"));
        seeds.put("int8", answer(20, "-9223372036854775808"));
        seeds.put("numeric", answer(1700, "12345.678900"));
        seeds.put("float8", answer(701, "1.5e300"));
        seeds.put("bool", answer(16, "t"));
        seeds.put("bytea", answer(17, "\\x0001feff"));
        seeds.put("date", answer(1082, "2026-11-26"));
        seeds.put("time", answer(1083, "23:59:59.999999"));
        seeds.put("timestamp", answer(1114, "2026-11-26 07:59:59.123456"));
        seeds.put("timestamptz", answer(1184, "2026-11-26 07:59:59.123456+01"));
        seeds.put("uuid", answer(2950, "123e4567-e89b-12d3-a456-426614174000"));
        seeds.put("text", answer(25, "a value"));
        seeds.put("int4 array", answer(1007, "{1,2,NULL,4}"));
        // Values a converter does not take, each where it meets one.
        seeds.put("int4 not a number", answer(23, "12x"));
        seeds.put("int8 beyond range", answer(20, "99999999999999999999999"));
        seeds.put("numeric huge exponent", answer(1700, "1e999999999"));
        seeds.put("float8 nonsense", answer(701, "1.5e3e3"));
        seeds.put("bool neither", answer(16, "maybe"));
        seeds.put("bytea cut in half", answer(17, "\\x0"));
        seeds.put("bytea bad escape", answer(17, "\\9"));
        seeds.put("date out of calendar", answer(1082, "2026-13-45"));
        seeds.put("time out of clock", answer(1083, "25:61:61"));
        seeds.put("timestamp infinity", answer(1114, "infinity"));
        seeds.put("timestamptz bad zone", answer(1184, "2026-11-26 07:59:59+99:99"));
        seeds.put("uuid short", answer(2950, "123e4567"));
        seeds.put("array unclosed", answer(1007, "{1,2,"));
        seeds.put("array nested deep", answer(1007, "{".repeat(200) + "}".repeat(200)));
        return seeds;
    }

    private static Map<String, String> parameters() {
        return Map.of("client_encoding", "UTF8", "DateStyle", "ISO, MDY",
                "integer_datetimes", "on", "TimeZone", "UTC", "server_version", "18.0");
    }

    /** Every getter on every column of every row; only SQLException may come out of one. */
    static void readEverything(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select v from t")) {
            int columns = rows.getMetaData().getColumnCount();
            while (rows.next()) {
                for (int column = 1; column <= columns; column++) {
                    for (Getter getter : GETTERS) {
                        try {
                            getter.read(rows, column);
                        } catch (SQLException refused) {
                            // A value this getter does not take: allowed.
                        }
                    }
                }
            }
        }
    }

    @FunctionalInterface
    interface Getter {
        Object read(ResultSet rows, int column) throws SQLException;
    }

    static final List<Getter> GETTERS = List.of(
            ResultSet::getString, ResultSet::getBoolean, ResultSet::getByte,
            ResultSet::getShort, ResultSet::getInt, ResultSet::getLong, ResultSet::getFloat,
            ResultSet::getDouble, ResultSet::getBigDecimal, ResultSet::getBytes,
            ResultSet::getDate, ResultSet::getTime, ResultSet::getTimestamp,
            ResultSet::getObject, ResultSet::getArray,
            (rows, column) -> rows.getObject(column, java.time.LocalDate.class),
            (rows, column) -> rows.getObject(column, java.time.LocalDateTime.class),
            (rows, column) -> rows.getObject(column, java.time.OffsetDateTime.class),
            (rows, column) -> rows.getObject(column, java.util.UUID.class));

    /**
     * The seeds themselves are read to the end: a sweep in which every case is
     * refused before the first getter proves nothing about the getters.
     */
    @Test
    void theSeedsReachTheGetters() throws Exception {
        for (Map.Entry<String, byte[]> seed : seeds().entrySet()) {
            PgSession session = PgSession.resume(HostileTransport.of(seed.getValue()),
                    parameters(), 1, 2);
            try (Connection connection = PgConnection.resume(session,
                    space.seclume.internal.jdbc.ConnectionFacts.fresh(
                            Connection.TRANSACTION_READ_COMMITTED));
                 Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select v from t")) {
                // The row arrived: the getters are next. Whether they take
                // the value is the sweep's question.
                org.junit.jupiter.api.Assertions.assertTrue(rows.next(), seed.getKey());
            }
        }
    }

    @Test
    void everyGetterSurvivesAHostileValue() {
        SessionContract.sweep("PostgreSQL getters", seeds(), script -> {
            PgSession session = PgSession.resume(HostileTransport.of(script), parameters(), 1, 2);
            Connection connection = PgConnection.resume(session,
                    space.seclume.internal.jdbc.ConnectionFacts.fresh(
                    Connection.TRANSACTION_READ_COMMITTED));
            return new SessionContract.Driven(() -> readEverything(connection),
                    session::isOpen, connection);
        });
    }
}
