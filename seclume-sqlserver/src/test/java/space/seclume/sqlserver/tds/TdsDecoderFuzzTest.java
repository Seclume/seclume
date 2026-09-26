package space.seclume.sqlserver.tds;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.fuzz.HostileTransport;
import space.seclume.tck.fuzz.SessionContract;

/**
 * The SQL Server decoders, driven by a server that sends nonsense.
 *
 * <p>TDS answers are a stream of <b>tokens</b>, each of which says what it is
 * and then how much of it there is - {@code COLMETADATA} describing the
 * columns, {@code ROW} carrying the values, {@code DONE} ending the batch.
 * Two sizes appear over and over and both come off the wire: the count of
 * columns, and the length of a variable-length value.
 *
 * <p>The seeds are honest tokens so the reader gets past the first one. What
 * the corpus then does to them - a column count that disagrees with the
 * columns, a value length larger than the packet, a token tag nobody knows -
 * is what a confused or malicious server sends.
 *
 * <p>Strings here are UTF-16, which is worth stating because it doubles every
 * length and makes an odd length a thing that cannot be right.
 */
@Timeout(1200)
class TdsDecoderFuzzTest {

    private static final int HEADER = 8;
    private static final int TYPE_TABULAR_RESULT = 0x04;
    private static final int END_OF_MESSAGE = 0x01;

    private static byte[] packet(int status, byte[] payload) {
        int length = HEADER + payload.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(TYPE_TABULAR_RESULT);
        out.write(status);
        out.write((length >> 8) & 0xff);
        out.write(length & 0xff);
        out.write(0x00);
        out.write(0x33);
        out.write(0x01);
        out.write(0x00);
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

    /** A column name: one byte of length in characters, then UTF-16. */
    private static void name(ByteArrayOutputStream out, String value) {
        out.write(value.length());
        out.writeBytes(value.getBytes(StandardCharsets.UTF_16LE));
    }

    /** COLMETADATA for one INTN column. */
    private static byte[] intColumn() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x81);                       // COLMETADATA
        out.write(0x01);
        out.write(0x00);                       // one column
        out.write(0x00);
        out.write(0x00);
        out.write(0x00);
        out.write(0x00);                       // user type
        out.write(0x09);
        out.write(0x00);                       // flags: nullable
        out.write(0x26);                       // INTNTYPE
        out.write(0x04);                       // four bytes
        name(out, "n");
        return out.toByteArray();
    }

    /** COLMETADATA for one NVARCHAR column. */
    private static byte[] textColumn() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x81);
        out.write(0x01);
        out.write(0x00);
        out.write(0x00);
        out.write(0x00);
        out.write(0x00);
        out.write(0x00);
        out.write(0x09);
        out.write(0x00);
        out.write(0xe7);                       // NVARCHARTYPE
        out.write(0x64);
        out.write(0x00);                       // max length
        out.write(0x09);
        out.write(0x04);
        out.write(0xd0);
        out.write(0x00);
        out.write(0x34);                       // collation
        name(out, "n");
        return out.toByteArray();
    }

    private static byte[] intRow(int value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xd1);                       // ROW
        out.write(0x04);                       // this value is four bytes
        out.write(value & 0xff);
        out.write((value >> 8) & 0xff);
        out.write((value >> 16) & 0xff);
        out.write((value >> 24) & 0xff);
        return out.toByteArray();
    }

    private static byte[] textRow(String value) {
        byte[] utf16 = value.getBytes(StandardCharsets.UTF_16LE);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xd1);
        out.write(utf16.length & 0xff);
        out.write((utf16.length >> 8) & 0xff);
        out.writeBytes(utf16);
        return out.toByteArray();
    }

    private static byte[] nullRow() {
        return new byte[] {(byte) 0xd1, 0x00};
    }

    private static byte[] done(int rows) {
        return new byte[] {(byte) 0xfd, 0x10, 0x00, 0x00, 0x00,
            (byte) rows, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    }

    private static Map<String, byte[]> seeds() {
        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("one integer row",
                packet(END_OF_MESSAGE, join(intColumn(), intRow(7), done(1))));
        seeds.put("one text row",
                packet(END_OF_MESSAGE, join(textColumn(), textRow("seven"), done(1))));
        seeds.put("a null",
                packet(END_OF_MESSAGE, join(intColumn(), nullRow(), done(1))));
        seeds.put("no rows", packet(END_OF_MESSAGE, join(intColumn(), done(0))));
        seeds.put("two rows over two packets",
                join(packet(0, join(intColumn(), intRow(1))),
                        packet(END_OF_MESSAGE, join(intRow(2), done(2)))));
        return seeds;
    }

    @Test
    void theDecodersSurviveAHostileServer() {
        SessionContract.sweep("SQL Server decoders", seeds(), script -> {
            TdsSession session = TdsSession.resume(HostileTransport.of(script),
                    4096, "master", "seclume", 16);
            return new SessionContract.Driven(
                    () -> session.askOneValue("select n from t"),
                    session::isOpen,
                    session);
        });
    }

    /** The same, a byte at a time, on a subset for the sake of the clock. */
    @Test
    void theDecodersSurviveAServerThatDribbles() {
        Map<String, byte[]> fewer = new LinkedHashMap<>(seeds());
        fewer.keySet().retainAll(java.util.List.of("one text row", "a null"));
        SessionContract.sweep("SQL Server decoders, a byte at a time", fewer, script -> {
            TdsSession session = TdsSession.resume(HostileTransport.of(script, 1),
                    4096, "master", "seclume", 16);
            return new SessionContract.Driven(
                    () -> session.askOneValue("select n from t"),
                    session::isOpen,
                    session);
        });
    }

    /** The same contract, with Jazzer choosing the answers. */
    @com.code_intelligence.jazzer.junit.FuzzTest(maxDuration = "60s")
    void coverageGuided(byte[] script) {
        TdsSession session = TdsSession.resume(HostileTransport.of(script),
                4096, "master", "seclume", 16);
        SessionContract.require(new SessionContract.Driven(
                () -> session.askOneValue("select n from t"), session::isOpen, session));
    }
}
