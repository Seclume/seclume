package space.seclume.oracle.net;

import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.fuzz.FuzzRun;

/**
 * The Oracle answer boundary, attacked - on both header shapes.
 *
 * <p>TTC is the one of the four where the end of an answer cannot be seen in
 * the packet header alone. A data packet carries two bytes of flags after the
 * header and one bit of those says the call is over; a marker packet carries
 * three and the third says which marker it is. So this walker reads past the
 * header into the body before it can decide, and that <b>extra</b> can be
 * split across reads like anything else - a third piece of state on top of the
 * header and the body.
 *
 * <p>And the header itself is not one shape but two: the length field is two
 * bytes below protocol version 315 and four from there on. That is a
 * negotiated fact, so the same bytes mean different things on two connections,
 * and both are fuzzed here rather than only the modern one.
 *
 * <p>One arithmetic detail is worth the attention it gets in the seeds:
 * {@code remaining = announced - HEADER - extraWant}. A packet that announces
 * less than it must contain would make that negative, which is why
 * {@code extraWant} is clamped to what the packet actually holds - and a
 * packet sized exactly at the boundary is in the corpus for it.
 */
@Timeout(180)
class OracleAnswersFuzzTest {

    private static final int HEADER = 8;
    private static final int END_OF_ANSWER = 0x2000;

    /** A packet with a two-byte length - the shape before version 315. */
    private static byte[] small(int type, byte[] body) {
        return header(type, body, false);
    }

    /** A packet with a four-byte length - version 315 and above. */
    private static byte[] large(int type, byte[] body) {
        return header(type, body, true);
    }

    private static byte[] header(int type, byte[] body, boolean fourByteLength) {
        int length = HEADER + body.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (fourByteLength) {
            out.write((length >> 24) & 0xff);
            out.write((length >> 16) & 0xff);
        } else {
            out.write((length >> 8) & 0xff);
            out.write(length & 0xff);
        }
        if (fourByteLength) {
            out.write((length >> 8) & 0xff);
            out.write(length & 0xff);
        } else {
            out.write(0x00);        // checksum, unused
            out.write(0x00);
        }
        out.write(type);
        out.write(0x00);            // reserved
        out.write(0x00);            // header checksum
        out.write(0x00);
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

    private static byte[] dataFlags(int flags, byte[] payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((flags >> 8) & 0xff);
        out.write(flags & 0xff);
        out.writeBytes(payload);
        return out.toByteArray();
    }

    private static Map<String, byte[]> seeds(boolean large) {
        java.util.function.BiFunction<Integer, byte[], byte[]> packet =
                large ? OracleAnswersFuzzTest::large : OracleAnswersFuzzTest::small;

        byte[] answerEnds = packet.apply(NsPacket.TYPE_DATA,
                dataFlags(END_OF_ANSWER, new byte[] {0x04, 0x01, 0x00}));
        byte[] moreToCome = packet.apply(NsPacket.TYPE_DATA,
                dataFlags(0, new byte[] {0x06, 0x01, 0x02, 0x03}));
        byte[] reset = packet.apply(NsPacket.TYPE_MARKER,
                new byte[] {0x01, 0x00, NsPacket.MARKER_TYPE_RESET});
        byte[] interrupt = packet.apply(NsPacket.TYPE_MARKER, new byte[] {0x01, 0x00, 0x01});
        // Exactly the header and the flags and not one byte more: the case the
        // clamp on extraWant exists for.
        byte[] bare = packet.apply(NsPacket.TYPE_DATA, dataFlags(END_OF_ANSWER, new byte[0]));
        // A packet too short for the flags its type usually carries.
        byte[] tooShort = packet.apply(NsPacket.TYPE_DATA, new byte[] {0x20});

        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("data, end of answer", answerEnds);
        seeds.put("data, more to come, then the end", join(moreToCome, answerEnds));
        seeds.put("marker reset", reset);
        seeds.put("marker interrupt then reset", join(interrupt, reset));
        seeds.put("header and flags only", bare);
        seeds.put("shorter than its own flags", tooShort);
        return seeds;
    }

    @Test
    void theTwoByteHeaderSurvivesAHostileServer() {
        FuzzRun.against("OracleAnswers(small header)",
                () -> new OracleAnswers(NsPacket.VERSION_MIN_LARGE_SDU - 1), seeds(false));
    }

    @Test
    void theFourByteHeaderSurvivesAHostileServer() {
        FuzzRun.against("OracleAnswers(large header)",
                () -> new OracleAnswers(NsPacket.VERSION_MIN_LARGE_SDU), seeds(true));
    }
}
