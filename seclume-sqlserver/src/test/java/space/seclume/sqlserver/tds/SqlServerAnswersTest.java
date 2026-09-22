package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;

import org.junit.jupiter.api.Test;

/**
 * Where a TDS answer ends: at the packet that says it is the last one.
 *
 * <p>The case worth writing down is the one in the middle of the second test.
 * A response carries a {@code DONE} token per statement, and the byte that
 * introduces one - {@code 0xfd}, or {@code 0xff} for {@code DONE_IN_PROC} - is
 * ordinary content here. A boundary that looked for tokens would cut an answer
 * into as many pieces as the batch has statements; this one never looks.
 */
class SqlServerAnswersTest {

    private static final int END_OF_MESSAGE = 0x01;

    private static void packet(ByteArrayOutputStream out, boolean last, byte... payload) {
        int length = payload.length + 8;
        out.write(0x04);                                   // a tabular result
        out.write(last ? END_OF_MESSAGE : 0x00);
        out.write((length >>> 8) & 0xff);                  // big endian, header included
        out.write(length & 0xff);
        out.write(0);
        out.write(0);
        out.write(1);
        out.write(0);
        out.writeBytes(payload);
    }

    @Test
    void oneFinalPacketIsTheWholeAnswer() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        packet(out, true, (byte) 0xfd, (byte) 0, (byte) 0, (byte) 0, (byte) 1);
        byte[] answer = out.toByteArray();
        assertEquals(answer.length,
                new SqlServerAnswers().endOfAnswer(answer, 0, answer.length));
    }

    /** Several packets, with DONE tokens inside them, and one end. */
    @Test
    void doneTokensInsideAnAnswerAreNotItsEnd() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Two statements' worth of DONE_IN_PROC, spread across packets that do
        // not carry the end-of-message bit.
        packet(out, false, (byte) 0xff, (byte) 0, (byte) 0, (byte) 0, (byte) 1, (byte) 0);
        packet(out, false, (byte) 0xff, (byte) 0, (byte) 0, (byte) 0, (byte) 1, (byte) 0);
        packet(out, true, (byte) 0xfd, (byte) 0, (byte) 0, (byte) 0, (byte) 0);
        byte[] answer = out.toByteArray();
        assertEquals(answer.length,
                new SqlServerAnswers().endOfAnswer(answer, 0, answer.length),
                "a DONE token inside the answer was taken for its end");
    }

    @Test
    void whatComesAfterTheAnswerIsNotPartOfIt() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        packet(out, true, (byte) 0xfd, (byte) 0);
        int first = out.size();
        packet(out, true, (byte) 0xfd, (byte) 0);
        byte[] two = out.toByteArray();
        assertEquals(first, new SqlServerAnswers().endOfAnswer(two, 0, two.length));
    }

    @Test
    void aSplitAtAnyByteFindsTheSameEnd() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        packet(out, false, (byte) 0x81, (byte) 1, (byte) 0);
        packet(out, true, (byte) 0xfd, (byte) 0, (byte) 0, (byte) 0, (byte) 1);
        byte[] answer = out.toByteArray();
        for (int cut = 1; cut < answer.length; cut++) {
            SqlServerAnswers boundary = new SqlServerAnswers();
            assertEquals(-1, boundary.endOfAnswer(answer, 0, cut),
                    "the answer cannot end inside the first " + cut + " bytes");
            assertEquals(answer.length - cut,
                    boundary.endOfAnswer(answer, cut, answer.length - cut),
                    "wrong end after a split at byte " + cut);
        }
    }

    /** A length that does not cover its own header is refused, not trusted. */
    @Test
    void aLengthThatMakesNoSenseIsRefused() {
        byte[] nonsense = {0x04, 0x01, 0x00, 0x03, 0, 0, 1, 0};
        SqlServerAnswers boundary = new SqlServerAnswers();
        assertThrows(IllegalStateException.class,
                () -> boundary.endOfAnswer(nonsense, 0, nonsense.length));
    }
}
