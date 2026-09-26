package space.seclume.postgresql;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.fuzz.HostileTransport;
import space.seclume.tck.fuzz.SessionContract;

/**
 * The PostgreSQL decoders, driven by a server that sends nonsense.
 *
 * <p>The boundary walker only has to find where an answer stops. Everything
 * behind it - row descriptions, field counts, per-column lengths, the text and
 * binary readers - turns bytes into values, and that is where a length off the
 * wire meets an allocator or an index.
 *
 * <p>{@code resume()} is what makes this reachable without a server. A session
 * that takes up a stream somebody else authenticated needs no handshake, so
 * every byte of the script goes straight into the decoders, in the order the
 * real driver would read them.
 *
 * <p>Three fields in the seeds are the ones worth watching, and the corpus
 * spoils all three: the message length, <b>the column count in a
 * RowDescription</b>, and <b>the per-column length in a DataRow</b> - the last
 * being the only place in this protocol where a signed 32-bit number off the
 * wire says how much to read, with {@code -1} meaning NULL and everything else
 * below zero meaning nothing at all.
 */
@Timeout(1200)
class PgDecoderFuzzTest {

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

    private static byte[] join(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
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

    /** One column, named, of the given type. */
    private static byte[] rowDescription(String name, int typeOid, int typeLength) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int16(body, 1);                                   // one field
        body.writeBytes(name.getBytes(StandardCharsets.UTF_8));
        body.write(0);
        int32(body, 0);                                   // table oid
        int16(body, 0);                                   // column number
        int32(body, typeOid);
        int16(body, typeLength);
        int32(body, -1);                                  // type modifier
        int16(body, 0);                                   // text format
        return message('T', body.toByteArray());
    }

    private static byte[] dataRow(byte[] value) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int16(body, 1);
        if (value == null) {
            int32(body, -1);
        } else {
            int32(body, value.length);
            body.writeBytes(value);
        }
        return message('D', body.toByteArray());
    }

    private static Map<String, byte[]> seeds() {
        byte[] ready = message('Z', new byte[] {'I'});
        byte[] complete = message('C', "SELECT 1\0".getBytes(StandardCharsets.UTF_8));
        byte[] text = rowDescription("n", 25, -1);        // text
        byte[] integer = rowDescription("n", 23, 4);      // int4
        byte[] error = message('E',
                "SERROR\0C42601\0Msyntax error\0\0".getBytes(StandardCharsets.UTF_8));
        byte[] notice = message('N', "SNOTICE\0Mjust so you know\0\0"
                .getBytes(StandardCharsets.UTF_8));
        byte[] parameter = message('S', "client_encoding\0UTF8\0"
                .getBytes(StandardCharsets.UTF_8));

        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("one text row", join(text, dataRow("7".getBytes(StandardCharsets.UTF_8)),
                complete, ready));
        seeds.put("one integer row", join(integer,
                dataRow("7".getBytes(StandardCharsets.UTF_8)), complete, ready));
        seeds.put("a null", join(text, dataRow(null), complete, ready));
        seeds.put("an empty value", join(text, dataRow(new byte[0]), complete, ready));
        seeds.put("no rows", join(text, complete, ready));
        seeds.put("an error", join(error, ready));
        seeds.put("a notice then a row", join(notice, text,
                dataRow("7".getBytes(StandardCharsets.UTF_8)), complete, ready));
        seeds.put("a parameter status then ready", join(parameter, complete, ready));
        return seeds;
    }

    private static Map<String, String> parameters() {
        return Map.of("client_encoding", "UTF8", "DateStyle", "ISO, MDY",
                "integer_datetimes", "on", "TimeZone", "UTC", "server_version", "18.0");
    }

    /**
     * A whole answer read the way a driver reads one, over a stream that
     * arrives in one piece.
     */
    @Test
    void theDecodersSurviveAHostileServer() {
        SessionContract.sweep("PostgreSQL decoders", seeds(), script -> {
            HostileTransport wire = HostileTransport.of(script);
            PgSession session = PgSession.resume(wire, parameters(), 1, 2);
            return new SessionContract.Driven(
                    () -> session.askOneValue("select n from t"),
                    session::isOpen,
                    session);
        });
    }

    /**
     * The same, a byte at a time.
     *
     * <p>Separate rather than folded in, because it asks a different question:
     * not what the decoder does with a bad value, but whether it keeps its
     * place when the value arrives in pieces. Those are different bugs and
     * they are found by different cases.
     */
    @Test
    void theDecodersSurviveAServerThatDribbles() {
        // A subset of the seeds, and deliberately: this sweep asks whether a
        // decoder keeps its place when a value arrives in pieces, and every
        // seed answers that equally well. Running all of them a byte at a time
        // costs minutes and finds the same thing.
        Map<String, byte[]> fewer = new LinkedHashMap<>(seeds());
        fewer.keySet().retainAll(java.util.List.of(
                "one text row", "a null", "a notice then a row"));
        SessionContract.sweep("PostgreSQL decoders, a byte at a time", fewer, script -> {
            HostileTransport wire = HostileTransport.of(script, 1);
            PgSession session = PgSession.resume(wire, parameters(), 1, 2);
            return new SessionContract.Driven(
                    () -> session.askOneValue("select n from t"),
                    session::isOpen,
                    session);
        });
    }

    /** The same contract, with Jazzer choosing the answers. */
    @com.code_intelligence.jazzer.junit.FuzzTest(maxDuration = "60s")
    void coverageGuided(byte[] script) {
        HostileTransport wire = HostileTransport.of(script);
        PgSession session = PgSession.resume(wire, parameters(), 1, 2);
        SessionContract.require(new SessionContract.Driven(
                () -> session.askOneValue("select n from t"), session::isOpen, session));
    }
}
