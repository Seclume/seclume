package space.seclume.tck.fuzz;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.AnswerBoundary;

/**
 * The contract's own control: four broken walkers it has to catch.
 *
 * <p>Written before the first real fuzz run was believed, and for the reason
 * this project ran into twice yesterday - once on Oracle's recycled
 * {@code SID}, once on SQL Server's {@code @@SPID}: <b>a test whose control
 * cannot fail is not a test.</b> A corpus of thousands of hostile blocks that
 * reports "no findings" is worth exactly as much as the harness's ability to
 * report one, and nothing more.
 *
 * <p>So each of the five questions gets a mutant that answers it wrongly, and
 * each mutant has to be caught. The mutants are deliberately small - one line
 * away from correct - because that is the size of the mistake a real parser
 * makes.
 */
@Timeout(60)
class BoundaryContractTest {

    /**
     * A correct walker, and the shape all the mutants are one change away
     * from: fixed four-byte messages, the fourth of which ends an answer.
     */
    private static class Correct implements AnswerBoundary {
        int remaining;
        int seen;

        @Override
        public int endOfAnswer(byte[] data, int offset, int length) {
            int at = offset;
            int end = offset + length;
            while (at < end) {
                if (remaining > 0) {
                    int take = Math.min(remaining, end - at);
                    at += take;
                    remaining -= take;
                    if (remaining == 0 && ++seen % 4 == 0) {
                        return at - offset;
                    }
                    continue;
                }
                remaining = 4;
            }
            return -1;
        }

        @Override
        public void reset() {
            remaining = 0;
            seen = 0;
        }
    }

    private static byte[] stream() {
        byte[] bytes = new byte[64];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) i;
        }
        return bytes;
    }

    /** The harness has to pass something that is actually right. */
    @Test
    void aCorrectWalkerPasses() {
        BoundaryContract.Reading reading =
                BoundaryContract.check("Correct", Correct::new, stream());
        assertTrue(reading.failure() == null, reading.describe());
        assertTrue(!reading.answerEnds().isEmpty(), "this stream should hold whole answers");
    }

    /** Question 3: a cursor that does not move. */
    @Test
    void aHangIsCaught() {
        AssertionError caught = assertThrows(AssertionError.class,
                () -> BoundaryContract.check("Hangs", () -> new AnswerBoundary() {
                    @Override
                    public int endOfAnswer(byte[] data, int offset, int length) {
                        while (length > 0) {
                            // The classic: the condition is on a value the body
                            // never changes.
                        }
                        return -1;
                    }

                    @Override
                    public void reset() {
                    }
                }, stream()));
        System.err.println("[contract] hang -> " + firstLine(caught));
    }

    /** Question 2: an answer longer than the block it was given. */
    @Test
    void anImpossibleCountIsCaught() {
        AssertionError caught = assertThrows(AssertionError.class,
                () -> BoundaryContract.check("Overruns", () -> new AnswerBoundary() {
                    @Override
                    public int endOfAnswer(byte[] data, int offset, int length) {
                        return length + 1;
                    }

                    @Override
                    public void reset() {
                    }
                }, stream()));
        System.err.println("[contract] overrun -> " + firstLine(caught));
    }

    /**
     * Question 1: reading outside the window.
     *
     * <p>Java cannot see a read that stays inside the array, so this is caught
     * by its effect: the same block is read twice with different padding, and
     * a walker that looks at the padding answers differently the second time.
     */
    @Test
    void readingPastTheWindowIsCaught() {
        AssertionError caught = assertThrows(AssertionError.class,
                () -> BoundaryContract.check("Peeks", () -> new AnswerBoundary() {
                    @Override
                    public int endOfAnswer(byte[] data, int offset, int length) {
                        // One byte before what it was given - an off-by-one in
                        // a header index, which is how this happens in earnest.
                        return offset > 0 && data[offset - 1] == 0 ? -1 : Math.min(4, length);
                    }

                    @Override
                    public void reset() {
                    }
                }, stream()));
        System.err.println("[contract] peeking past the window -> " + firstLine(caught));
    }

    /**
     * Question 4: a walker that forgets what it half saw.
     *
     * <p>The most valuable of the five, because this is the bug that passes
     * every hand-written test - they hand over whole messages - and then
     * appears in production as "it works except under load".
     */
    @Test
    void forgettingAHalfSeenHeaderIsCaught() {
        AssertionError caught = assertThrows(AssertionError.class,
                () -> BoundaryContract.check("Forgets", () -> new AnswerBoundary() {
                    @Override
                    public int endOfAnswer(byte[] data, int offset, int length) {
                        // Keeps nothing across calls: whole blocks are read
                        // correctly, split ones start over every time.
                        int at = 0;
                        int seen = 0;
                        while (at + 4 <= length) {
                            at += 4;
                            if (++seen % 4 == 0) {
                                return at;
                            }
                        }
                        return -1;
                    }

                    @Override
                    public void reset() {
                    }
                }, stream()));
        System.err.println("[contract] a forgotten header -> " + firstLine(caught));
    }

    private static String firstLine(Throwable thrown) {
        String message = String.valueOf(thrown.getMessage());
        int newline = message.indexOf('\n');
        return newline < 0 ? message : message.substring(0, newline);
    }
}
