package space.seclume.postgresql.wire;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * Where an answer ends, pinned as a number.
 *
 * <p>This test exists because of a control run that should have gone red and
 * did not. The re-association tests were passing with the boundary
 * deliberately moved from {@code ReadyForQuery} to {@code CommandComplete} -
 * and they were right to: with a request-and-answer discipline, an answer cut
 * one message early leaves that message carried into the next answer, and
 * every assertion about rows and tags still finds what it looks for. The
 * conversation stays consistent while being wrong.
 *
 * <p>Which is precisely why the boundary needs a test of its own. What the
 * cut-short version loses is not a row but the <b>transaction status</b>: the
 * one byte in {@code ReadyForQuery} that says whether a transaction is open.
 * A successor attaching at such a point would be told nothing about it, and
 * that is the state on which the whole slot design turns.
 */
class PostgresAnswersTest {

    /** T, D, C, Z - a select as the server answers it. */
    private static byte[] anAnswer(char transactionStatus) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        message(out, 'T', new byte[] {0, 1});                       // one column
        message(out, 'D', new byte[] {0, 1, 0, 0, 0, 1, '7'});      // one row, "7"
        message(out, 'C', "SELECT 1\0".getBytes(StandardCharsets.UTF_8));
        message(out, 'Z', new byte[] {(byte) transactionStatus});
        return out.toByteArray();
    }

    private static void message(ByteArrayOutputStream out, char type, byte[] body) {
        out.write(type);
        int length = body.length + 4;
        out.write(length >>> 24);
        out.write(length >>> 16);
        out.write(length >>> 8);
        out.write(length);
        out.writeBytes(body);
    }

    @Test
    void theAnswerEndsAfterReadyForQueryAndNotBefore() {
        byte[] answer = anAnswer('T');
        assertEquals(answer.length, new PostgresAnswers().endOfAnswer(answer, 0, answer.length),
                "the answer has to end on the last byte of ReadyForQuery - one message earlier "
                + "still carries every row and loses the transaction status");
    }

    /** What follows the answer belongs to the next one and must not be eaten. */
    @Test
    void whatComesAfterTheAnswerIsNotPartOfIt() {
        byte[] answer = anAnswer('I');
        byte[] two = new byte[answer.length * 2];
        System.arraycopy(answer, 0, two, 0, answer.length);
        System.arraycopy(answer, 0, two, answer.length, answer.length);
        assertEquals(answer.length, new PostgresAnswers().endOfAnswer(two, 0, two.length),
                "the first answer ends where the second begins");
    }

    /**
     * The same answer, delivered in every possible split.
     *
     * <p>A message may be cut at any byte - a header across two reads is the
     * ordinary case on a busy socket, not a corner one. Feeding the answer as
     * two blocks at every offset is the cheapest way to say that once.
     */
    @Test
    void aSplitAtAnyByteFindsTheSameEnd() {
        byte[] answer = anAnswer('T');
        for (int cut = 1; cut < answer.length; cut++) {
            PostgresAnswers boundary = new PostgresAnswers();
            assertEquals(-1, boundary.endOfAnswer(answer, 0, cut),
                    "the answer cannot end inside the first " + cut + " bytes");
            assertEquals(answer.length - cut,
                    boundary.endOfAnswer(answer, cut, answer.length - cut),
                    "wrong end after a split at byte " + cut);
        }
    }

    /** A length that does not cover its own field is refused, not allocated for. */
    @Test
    void aLengthThatMakesNoSenseIsRefused() {
        byte[] nonsense = {'D', 0, 0, 0, 1, 0, 0};
        PostgresAnswers boundary = new PostgresAnswers();
        assertThrows(IllegalStateException.class,
                () -> boundary.endOfAnswer(nonsense, 0, nonsense.length));
    }
}
