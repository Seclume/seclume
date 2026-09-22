package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;

import org.junit.jupiter.api.Test;

/**
 * Where an Oracle answer ends: at the packet whose data flags say so.
 *
 * <p>Two things are worth a test rather than a sentence. A marker packet - the
 * server's way of breaking off a call - travels through the middle of a
 * conversation and ends nothing, and it carries no data flags at all, so a
 * boundary that read two bytes of flags from it would be two bytes out of step
 * for the rest of the stream. And the length field is two bytes or four
 * depending on what was negotiated, which is why the boundary is told the
 * protocol version rather than sniffing it.
 */
class OracleAnswersTest {

    private static final int END_OF_ANSWER = 0x2000;
    private static final int OLD = NsPacket.VERSION_MINIMUM;
    private static final int LARGE = NsPacket.VERSION_DESIRED;

    private static void data(ByteArrayOutputStream out, boolean large, boolean last,
                             byte... payload) {
        int length = NsPacket.HEADER_SIZE + NsPacket.DATA_FLAGS_SIZE + payload.length;
        header(out, large, length, NsPacket.TYPE_DATA);
        int flags = last ? END_OF_ANSWER : 0;
        out.write((flags >>> 8) & 0xff);
        out.write(flags & 0xff);
        out.writeBytes(payload);
    }

    /**
     * A marker: eight bytes of header and three of body, the last of which
     * says which kind it is. No data flags - a marker is not a DATA packet.
     */
    private static void marker(ByteArrayOutputStream out, boolean large, int kind) {
        header(out, large, NsPacket.HEADER_SIZE + 3, NsPacket.TYPE_MARKER);
        out.write(1);
        out.write(0);
        out.write(kind);
    }

    /**
     * Eight bytes, whichever length width is in use - that is the point of the
     * large form: it takes the checksum's two bytes rather than adding any.
     */
    private static void header(ByteArrayOutputStream out, boolean large, int length, int type) {
        if (large) {
            out.write((length >>> 24) & 0xff);
            out.write((length >>> 16) & 0xff);
            out.write((length >>> 8) & 0xff);
            out.write(length & 0xff);
        } else {
            out.write((length >>> 8) & 0xff);
            out.write(length & 0xff);
            out.write(0);                               // packet checksum
            out.write(0);
        }
        out.write(type);
        out.write(0);                                   // flags
        out.write(0);                                   // header checksum
        out.write(0);
    }

    @Test
    void theAnswerEndsAtThePacketThatSaysSo() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        data(out, true, false, (byte) 0x06, (byte) 0x01);
        data(out, true, false, (byte) 0x07, (byte) 0x02);
        data(out, true, true, (byte) 0x04, (byte) 0x00);
        byte[] answer = out.toByteArray();
        assertEquals(answer.length, new OracleAnswers(LARGE).endOfAnswer(answer, 0, answer.length));
    }

    /** What follows belongs to the next answer. */
    @Test
    void whatComesAfterTheAnswerIsNotPartOfIt() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        data(out, true, true, (byte) 0x04);
        int first = out.size();
        data(out, true, true, (byte) 0x04);
        byte[] two = out.toByteArray();
        assertEquals(first, new OracleAnswers(LARGE).endOfAnswer(two, 0, two.length));
    }

    /**
     * A break marker in the middle ends nothing - and must not be read as
     * though it had data flags.
     */
    @Test
    void aBreakMarkerTravelsThroughWithoutEndingAnything() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        data(out, true, false, (byte) 0x06);
        marker(out, true, NsPacket.MARKER_TYPE_BREAK);
        data(out, true, true, (byte) 0x04);
        byte[] answer = out.toByteArray();
        assertEquals(answer.length, new OracleAnswers(LARGE).endOfAnswer(answer, 0, answer.length),
                "the break marker threw the framing out of step");
    }

    /**
     * The reset marker does end one, and that is what keeps a failed
     * statement from hanging the connection.
     *
     * <p>Oracle answers a failure with break and reset and then waits for the
     * client's reset before it sends the error at all. The driver behind a
     * relay can only send that if the markers reach it, so the answer has to
     * end here - with the whole pair in it, because a break on its own is
     * half a conversation.
     */
    @Test
    void theResetMarkerEndsTheAnswerSoTheDriverCanAnswerIt() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        marker(out, true, NsPacket.MARKER_TYPE_BREAK);
        marker(out, true, NsPacket.MARKER_TYPE_RESET);
        int pair = out.size();
        // What the server sends only after the client's reset - it must not
        // be part of this answer, because it has not been asked for yet.
        data(out, true, true, (byte) 0x04);
        byte[] stream = out.toByteArray();
        assertEquals(pair, new OracleAnswers(LARGE).endOfAnswer(stream, 0, stream.length),
                "the answer must end at the reset marker");
    }

    /** The same, arriving one byte at a time. */
    @Test
    void theMarkerPairSurvivesAnySplit() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        marker(out, true, NsPacket.MARKER_TYPE_BREAK);
        marker(out, true, NsPacket.MARKER_TYPE_RESET);
        byte[] pair = out.toByteArray();
        for (int cut = 1; cut < pair.length; cut++) {
            OracleAnswers boundary = new OracleAnswers(LARGE);
            assertEquals(-1, boundary.endOfAnswer(pair, 0, cut),
                    "the pair cannot have ended inside the first " + cut + " bytes");
            assertEquals(pair.length - cut,
                    boundary.endOfAnswer(pair, cut, pair.length - cut),
                    "wrong end after a split at byte " + cut);
        }
    }

    /** The old two-byte length, which older servers still negotiate. */
    @Test
    void theShortLengthFieldWorksToo() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        data(out, false, false, (byte) 0x06);
        data(out, false, true, (byte) 0x04);
        byte[] answer = out.toByteArray();
        assertEquals(answer.length, new OracleAnswers(OLD).endOfAnswer(answer, 0, answer.length));
    }

    @Test
    void aSplitAtAnyByteFindsTheSameEnd() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        data(out, true, false, (byte) 0x06, (byte) 0x01, (byte) 0x02);
        marker(out, true, NsPacket.MARKER_TYPE_BREAK);
        data(out, true, true, (byte) 0x04, (byte) 0x00);
        byte[] answer = out.toByteArray();
        for (int cut = 1; cut < answer.length; cut++) {
            OracleAnswers boundary = new OracleAnswers(LARGE);
            assertEquals(-1, boundary.endOfAnswer(answer, 0, cut),
                    "the answer cannot end inside the first " + cut + " bytes");
            assertEquals(answer.length - cut,
                    boundary.endOfAnswer(answer, cut, answer.length - cut),
                    "wrong end after a split at byte " + cut);
        }
    }

    @Test
    void aLengthThatMakesNoSenseIsRefused() {
        byte[] nonsense = {0, 0, 0, 3, 0, 0, 6, 0, 0, 0};
        OracleAnswers boundary = new OracleAnswers(LARGE);
        assertThrows(IllegalStateException.class,
                () -> boundary.endOfAnswer(nonsense, 0, nonsense.length));
    }
}
