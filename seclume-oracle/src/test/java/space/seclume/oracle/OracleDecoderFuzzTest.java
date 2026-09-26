package space.seclume.oracle;

import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.oracle.net.NsPacket;
import space.seclume.tck.fuzz.HostileTransport;
import space.seclume.tck.fuzz.SessionContract;

/**
 * The Oracle decoders, driven by a server that sends nonsense.
 *
 * <p>TTC is the least forgiving of the four to hand-write, and that shapes
 * what this test honestly claims. A full result - describe, define, fetch -
 * is a long structure of length-prefixed fields inside a TTC message inside
 * an NS packet, and building a valid one by hand would be writing the server.
 * So the seeds are well-formed <b>packets</b> carrying TTC messages that are
 * plausible rather than complete.
 *
 * <p>That is less than the other three get, and it is still worth having:
 * <b>the requirement being tested is how the driver fails</b>, not how well
 * it decodes. An answer the reader cannot make sense of has to come back as a
 * {@code SQLException} that names something, leave the session closed, and
 * take neither the thread nor the heap with it - which is exactly where the
 * {@code Truncated} defect lived, and it lived in the login path of this
 * driver too.
 *
 * <p>Two header shapes again, because the length field is two bytes below
 * protocol version 315 and four from there on, and a corpus that only knows
 * the modern one leaves half the framing untried.
 */
@Timeout(1200)
class OracleDecoderFuzzTest {

    private static final int HEADER = 8;
    private static final int END_OF_ANSWER = 0x2000;

    private static byte[] packet(int type, byte[] body, boolean fourByteLength) {
        int length = HEADER + body.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (fourByteLength) {
            out.write((length >> 24) & 0xff);
            out.write((length >> 16) & 0xff);
            out.write((length >> 8) & 0xff);
            out.write(length & 0xff);
        } else {
            out.write((length >> 8) & 0xff);
            out.write(length & 0xff);
            out.write(0x00);
            out.write(0x00);
        }
        out.write(type);
        out.write(0x00);
        out.write(0x00);
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

    /** A data packet: two bytes of flags, then a TTC message. */
    private static byte[] data(int flags, byte[] ttc, boolean large) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write((flags >> 8) & 0xff);
        body.write(flags & 0xff);
        body.writeBytes(ttc);
        return packet(NsPacket.TYPE_DATA, body.toByteArray(), large);
    }

    private static Map<String, byte[]> seeds(boolean large) {
        // TTC function 8 is a call's answer; 4 is an error return carrying the
        // ORA number. Neither is complete here, and the corpus spoils them
        // further - what is being asked is how the reader refuses.
        byte[] callAnswer = {0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
        byte[] errorReturn = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0x03, (byte) 0xe9};
        byte[] rowPrefix = {0x06, 0x01, 0x01, 0x01, 0x31};

        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("a call that ends the answer", data(END_OF_ANSWER, callAnswer, large));
        seeds.put("an error return", data(END_OF_ANSWER, errorReturn, large));
        seeds.put("a row then the end",
                join(data(0, rowPrefix, large), data(END_OF_ANSWER, callAnswer, large)));
        seeds.put("a marker then the end",
                join(packet(NsPacket.TYPE_MARKER,
                        new byte[] {0x01, 0x00, NsPacket.MARKER_TYPE_RESET}, large),
                        data(END_OF_ANSWER, callAnswer, large)));
        seeds.put("flags only", data(END_OF_ANSWER, new byte[0], large));
        return seeds;
    }

    private static int version(boolean large) {
        return large ? NsPacket.VERSION_MIN_LARGE_SDU : NsPacket.VERSION_MIN_LARGE_SDU - 1;
    }

    private void sweep(String what, boolean large, int... chunks) {
        SessionContract.sweep(what, seeds(large), script -> {
            OracleSession session = OracleSession.resume(
                    chunks.length == 0 ? HostileTransport.of(script)
                                       : HostileTransport.of(script, chunks),
                    version(large), 1, false);
            return new SessionContract.Driven(
                    () -> session.askOneValue("select n from t"),
                    session::isOpen,
                    session);
        });
    }

    @Test
    void theFourByteHeaderSurvivesAHostileServer() {
        sweep("Oracle decoders (large header)", true);
    }

    @Test
    void theTwoByteHeaderSurvivesAHostileServer() {
        sweep("Oracle decoders (small header)", false);
    }

    @Test
    void theDecodersSurviveAServerThatDribbles() {
        sweep("Oracle decoders, a byte at a time", true, 1);
    }

    /** The same contract, with Jazzer choosing the answers. */
    @com.code_intelligence.jazzer.junit.FuzzTest(maxDuration = "60s")
    void coverageGuided(byte[] script) {
        OracleSession session = OracleSession.resume(HostileTransport.of(script),
                version(false), 1, false);
        SessionContract.require(new SessionContract.Driven(
                () -> session.askOneValue("select n from t"), session::isOpen, session));
    }
}
