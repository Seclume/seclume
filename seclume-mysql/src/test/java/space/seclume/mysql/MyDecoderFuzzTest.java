package space.seclume.mysql;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.fuzz.HostileTransport;
import space.seclume.tck.fuzz.SessionContract;

/**
 * The MySQL decoders, driven by a server that sends nonsense.
 *
 * <p>MySQL puts more of its structure in the body than the other three: a
 * result set is a length-encoded column count, then that many column
 * definitions each of which is six length-encoded strings, then rows of
 * length-encoded values. <b>Every one of those is a byte announcing how many
 * bytes follow</b>, which is a great deal more surface than a fixed header.
 *
 * <p>The corpus knows the markers that introduce a length - {@code fb fc fd
 * fe} - because it had to learn them before it could find the defect in
 * {@code MySqlAnswers.lengthEncoded}. The same knowledge is what gives these
 * seeds a chance of reaching the value readers rather than being refused at
 * the packet header.
 */
@Timeout(1200)
class MyDecoderFuzzTest {

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

    /** A length-encoded string: one byte of length, then the bytes. */
    private static void lenenc(ByteArrayOutputStream out, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.write(bytes.length);
        out.writeBytes(bytes);
    }

    /** One column definition, in the shape the protocol gives it. */
    private static byte[] columnDefinition(int sequence, String name, int type) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        lenenc(body, "def");
        lenenc(body, "seclume_test");
        lenenc(body, "t");
        lenenc(body, "t");
        lenenc(body, name);
        lenenc(body, name);
        body.write(0x0c);                       // the fixed-length part follows
        body.write(0x3f);
        body.write(0x00);                       // character set: binary
        body.write(0x0b);
        body.write(0x00);
        body.write(0x00);
        body.write(0x00);                       // column length
        body.write(type);
        body.write(0x00);
        body.write(0x00);                       // flags
        body.write(0x00);                       // decimals
        body.write(0x00);
        body.write(0x00);
        return packet(sequence, body.toByteArray());
    }

    private static byte[] row(int sequence, String value) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        lenenc(body, value);
        return packet(sequence, body.toByteArray());
    }

    private static Map<String, byte[]> seeds() {
        byte[] columnCount = packet(1, new byte[] {0x01});
        byte[] longColumn = columnDefinition(2, "n", 0x03);     // MYSQL_TYPE_LONG
        byte[] varchar = columnDefinition(2, "n", 0x0f);        // MYSQL_TYPE_VARCHAR
        byte[] ok = packet(4, new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00});
        byte[] eof = packet(4, new byte[] {(byte) 0xfe, 0x00, 0x00, 0x02, 0x00});
        byte[] nullRow = packet(3, new byte[] {(byte) 0xfb});
        byte[] err = packet(1, join(new byte[] {(byte) 0xff, 0x15, 0x04, '#', '2', '8', '0',
            '0', '0'}, "Access denied".getBytes(StandardCharsets.UTF_8)));

        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("one integer row", join(columnCount, longColumn, row(3, "7"), ok));
        seeds.put("one text row", join(columnCount, varchar, row(3, "seven"), ok));
        seeds.put("a null", join(columnCount, varchar, nullRow, ok));
        seeds.put("an empty value", join(columnCount, varchar, row(3, ""), ok));
        seeds.put("no rows", join(columnCount, varchar, ok));
        seeds.put("an eof terminator", join(columnCount, varchar, row(3, "7"), eof));
        seeds.put("an error", err);
        return seeds;
    }

    @Test
    void theDecodersSurviveAHostileServer() {
        SessionContract.sweep("MySQL decoders", seeds(), script -> {
            MySession session = MySession.resume(HostileTransport.of(script), CAPABILITIES, 7);
            return new SessionContract.Driven(
                    () -> session.askOneValue("select n from t"),
                    session::isOpen,
                    session);
        });
    }

    /** The same, arriving a byte at a time, on a subset for the sake of the clock. */
    @Test
    void theDecodersSurviveAServerThatDribbles() {
        Map<String, byte[]> fewer = new LinkedHashMap<>(seeds());
        fewer.keySet().retainAll(java.util.List.of("one text row", "a null", "an error"));
        SessionContract.sweep("MySQL decoders, a byte at a time", fewer, script -> {
            MySession session = MySession.resume(
                    HostileTransport.of(script, 1), CAPABILITIES, 7);
            return new SessionContract.Driven(
                    () -> session.askOneValue("select n from t"),
                    session::isOpen,
                    session);
        });
    }

    /** The same contract, with Jazzer choosing the answers. */
    @com.code_intelligence.jazzer.junit.FuzzTest(maxDuration = "60s")
    void coverageGuided(byte[] script) {
        MySession session = MySession.resume(HostileTransport.of(script), CAPABILITIES, 7);
        SessionContract.require(new SessionContract.Driven(
                () -> session.askOneValue("select n from t"), session::isOpen, session));
    }
}
