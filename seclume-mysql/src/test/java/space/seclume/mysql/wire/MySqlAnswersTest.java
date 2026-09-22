package space.seclume.mysql.wire;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * Where a MySQL answer ends, pinned as a number.
 *
 * <p>The cases that matter are the ones where a byte lies. A row may begin
 * with {@code 0x00}, with {@code 0xff} or with {@code 0xfe} - those are
 * lengths, not types - so every test here contains at least one row that looks
 * like a terminator and must not be taken for one.
 *
 * <p>Built from synthetic packets rather than from a server, because what is
 * under test is the counting and not MySQL.
 */
class MySqlAnswersTest {

    private static final int DEPRECATE_EOF = 0x0100_0000;

    /** Header: three bytes of length, one of sequence. */
    private static void packet(ByteArrayOutputStream out, int sequence, byte... payload) {
        out.write(payload.length & 0xff);
        out.write((payload.length >>> 8) & 0xff);
        out.write((payload.length >>> 16) & 0xff);
        out.write(sequence);
        out.writeBytes(payload);
    }

    private static byte[] ok(int status) {
        // 0x00, affected rows, last insert id, status, warnings
        return new byte[] {0x00, 0x00, 0x00, (byte) (status & 0xff),
                           (byte) (status >>> 8), 0x00, 0x00};
    }

    private static byte[] eofShapedOk(int status) {
        return new byte[] {(byte) 0xfe, 0x00, 0x00, (byte) (status & 0xff),
                           (byte) (status >>> 8), 0x00, 0x00};
    }

    private static byte[] text(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        byte[] row = new byte[bytes.length + 1];
        row[0] = (byte) bytes.length;
        System.arraycopy(bytes, 0, row, 1, bytes.length);
        return row;
    }

    /** An update: one OK packet and nothing else. */
    @Test
    void anOkIsTheWholeAnswer() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        packet(out, 1, ok(0));
        byte[] answer = out.toByteArray();
        assertEquals(answer.length,
                new MySqlAnswers(DEPRECATE_EOF).endOfAnswer(answer, 0, answer.length));
    }

    /** An error, likewise. */
    @Test
    void anErrorIsTheWholeAnswer() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        packet(out, 1, new byte[] {(byte) 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'n', 'o'});
        byte[] answer = out.toByteArray();
        assertEquals(answer.length,
                new MySqlAnswers(DEPRECATE_EOF).endOfAnswer(answer, 0, answer.length));
    }

    /**
     * A result set whose rows start with the three bytes that end answers.
     *
     * <p>The whole point of the class: {@code 0x00} is an empty string,
     * {@code 0xfe} at the head of a long row is a length, and neither is a
     * terminator.
     */
    @Test
    void rowsThatLookLikeTerminatorsAreNotOne() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        packet(out, 1, new byte[] {0x01});                    // one column
        packet(out, 2, columnDefinition());
        packet(out, 3, new byte[] {0x00});                    // a row: empty string
        packet(out, 4, text("ordinary"));
        // A row of ten bytes beginning with 0xfe - data, because it is long.
        packet(out, 5, new byte[] {(byte) 0xfe, 1, 2, 3, 4, 5, 6, 7, 8, 9});
        packet(out, 6, eofShapedOk(0));                       // and this ends it
        byte[] answer = out.toByteArray();
        assertEquals(answer.length,
                new MySqlAnswers(DEPRECATE_EOF).endOfAnswer(answer, 0, answer.length));
    }

    /**
     * A procedure's two result sets are one answer.
     *
     * <p>{@code SERVER_MORE_RESULTS_EXISTS} in the first terminator says so,
     * and a boundary that stopped there would hand the caller half an answer
     * and leave the rest for the next request to trip over.
     */
    @Test
    void twoResultSetsAreOneAnswerWhenTheServerSaysSo() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        packet(out, 1, new byte[] {0x01});
        packet(out, 2, columnDefinition());
        packet(out, 3, text("first"));
        packet(out, 4, eofShapedOk(0x0008));                  // more results follow
        packet(out, 5, new byte[] {0x01});
        packet(out, 6, columnDefinition());
        packet(out, 7, text("second"));
        packet(out, 8, eofShapedOk(0));                       // now it ends
        byte[] answer = out.toByteArray();
        MySqlAnswers boundary = new MySqlAnswers(DEPRECATE_EOF);
        assertEquals(answer.length, boundary.endOfAnswer(answer, 0, answer.length),
                "the answer ended at the first result set, so the second would have "
                + "arrived as an answer to the next request");
    }

    /** What follows the answer belongs to the next one. */
    @Test
    void whatComesAfterTheAnswerIsNotPartOfIt() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        packet(out, 1, ok(0));
        int first = out.size();
        packet(out, 1, ok(0));
        byte[] two = out.toByteArray();
        assertEquals(first, new MySqlAnswers(DEPRECATE_EOF).endOfAnswer(two, 0, two.length));
    }

    /** And a split at any byte finds the same end. */
    @Test
    void aSplitAtAnyByteFindsTheSameEnd() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        packet(out, 1, new byte[] {0x01});
        packet(out, 2, columnDefinition());
        packet(out, 3, text("value"));
        packet(out, 4, eofShapedOk(0));
        byte[] answer = out.toByteArray();
        for (int cut = 1; cut < answer.length; cut++) {
            MySqlAnswers boundary = new MySqlAnswers(DEPRECATE_EOF);
            assertEquals(-1, boundary.endOfAnswer(answer, 0, cut),
                    "the answer cannot end inside the first " + cut + " bytes");
            assertEquals(answer.length - cut,
                    boundary.endOfAnswer(answer, cut, answer.length - cut),
                    "wrong end after a split at byte " + cut);
        }
    }

    /** A column definition, long enough that nothing mistakes it for a type. */
    private static byte[] columnDefinition() {
        byte[] definition = new byte[40];
        definition[0] = 0x03;
        definition[1] = 'd';
        definition[2] = 'e';
        definition[3] = 'f';
        return definition;
    }
}
