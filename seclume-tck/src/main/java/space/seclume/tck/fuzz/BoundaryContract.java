package space.seclume.tck.fuzz;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import space.seclume.internal.AnswerBoundary;

/**
 * What an {@link AnswerBoundary} must do when the bytes are hostile.
 *
 * <p>Four protocols are parsed by hand in this project, and every one of these
 * walkers reads a length off the wire and then believes it. The property tests
 * are good at valid values and at edges; they are not an adversary. This is the
 * adversary's side of the contract, and it is written as five questions that
 * can be answered mechanically about any implementation.
 *
 * <p><b>The reason this exists as a contract rather than as four tests</b> is
 * that the interface says what the method returns and nothing about what it may
 * do to get there. Read literally, an implementation that hangs, or that reads
 * past the window it was given, or that answers differently depending on how
 * the network happened to split the bytes, breaks no written rule. All three
 * are catastrophic in a relay.
 *
 * <h2>The five questions</h2>
 *
 * <ol>
 *   <li><b>Does it stay inside its window?</b> Detected rather than assumed:
 *       the block is handed over inside padding, the same block is read twice
 *       with two different paddings, and an implementation whose answer changes
 *       read bytes that were not its own. An {@code ArrayIndexOutOfBounds} is
 *       the same fault caught by the JVM instead.
 *   <li><b>Does it answer within its bounds?</b> Either {@code -1} or a count
 *       between 0 and {@code length}. A count larger than the block tells a
 *       relay to forward bytes it has not got.
 *   <li><b>Does it finish?</b> Every walker here advances a cursor inside a
 *       {@code while} loop, and the failure mode of that shape is a state in
 *       which the cursor does not move. A hang is worse than a crash: a crash
 *       names a connection, a hang takes the thread.
 *   <li><b>Is it indifferent to how the bytes arrived?</b> The strongest of the
 *       five and the cheapest, because it needs no notion of a correct answer.
 *       A message may be split at any byte - the interface says so - therefore
 *       the same stream delivered in one block, in single bytes, and in
 *       arbitrary chunks has to yield the same answer boundaries. Anything else
 *       means the parser's state does not survive a split, and the bug appears
 *       in production as "it works except under load".
 *   <li><b>Does it fail in a way somebody can act on?</b> A refusal is correct
 *       and often the only correct thing. What is not correct is a refusal
 *       carrying no message, or one of a type that says nothing - so the kind
 *       of failure is recorded and asserted on rather than swallowed.
 * </ol>
 *
 * <p>Note what is deliberately <b>not</b> asserted: that any particular stream
 * produces any particular boundary. That would need a second implementation of
 * four protocols, which is how a relay ends up with two readers that drift.
 * Everything here is a property the implementation has to have against itself.
 */
public final class BoundaryContract {

    /** How many loop iterations a reading may take before it is called a hang. */
    private static final int BUDGET = 1 << 20;

    /**
     * How long one stream may take before it is called a hang.
     *
     * <p>Generous on purpose: the corpus holds blocks of a few kilobytes read
     * a byte at a time, which is thousands of calls, and a loaded machine is
     * not a finding.
     */
    private static final long DEADLINE_MILLIS = 5_000;

    private BoundaryContract() {
    }

    /**
     * One thread, reused, and a new one only after a hang.
     *
     * <p>A thread per case is what the first version did, and with ten
     * thousand cases the JVM ran out of native threads and said so. A watchdog
     * that kills the run it is watching is not a watchdog. The executor is
     * thrown away only when an attempt did not come back - one abandoned
     * thread per finding rather than one per case.
     */
    private static java.util.concurrent.ExecutorService worker = newWorker();

    private static java.util.concurrent.ExecutorService newWorker() {
        return java.util.concurrent.Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "boundary-contract");
            thread.setDaemon(true);
            return thread;
        });
    }

    private static void giveUpOnTheWorker() {
        worker.shutdownNow();
        worker = newWorker();
    }

    /**
     * What one reading of a stream produced.
     *
     * @param answerEnds absolute offsets, one per answer that ended
     * @param failure    the exception the implementation threw, or {@code null}
     */
    public record Reading(List<Integer> answerEnds, Throwable failure) {

        /** For a message that names what went wrong without printing a stack. */
        public String describe() {
            return failure == null
                    ? "ends " + answerEnds
                    : failure.getClass().getSimpleName() + ": " + failure.getMessage();
        }
    }

    /**
     * Feeds a stream through a fresh boundary in the given chunks.
     *
     * <p>This is the caller a relay actually is: hand over what arrived, and
     * when the boundary says an answer ended inside the block, take up again
     * at the byte after it. Getting that loop wrong here would make every
     * result meaningless, so it is written once and shared.
     *
     * @param pad bytes placed on both sides of every block. Two readings with
     *            different padding must agree; where they do not, the
     *            implementation read outside its window
     */
    public static Reading read(Supplier<AnswerBoundary> boundary, byte[] stream,
            int[] chunks, byte pad) {
        AnswerBoundary reader = boundary.get();
        List<Integer> ends = new ArrayList<>();
        int at = 0;
        int chunk = 0;
        int spins = 0;
        while (at < stream.length) {
            int size = Math.min(chunks[chunk++ % chunks.length], stream.length - at);
            if (size <= 0) {
                size = stream.length - at;
            }
            int from = at;
            int left = size;
            while (left > 0) {
                if (++spins > BUDGET) {
                    // A breach, not a refusal: thrown rather than recorded, for
                    // the reason below.
                    throw new AssertionError("did not finish within " + BUDGET
                            + " steps - a cursor that stops advancing between calls is a "
                            + "hang, and a hang takes the thread\n  stream: " + hex(stream));
                }
                byte[] padded = new byte[16 + left + 16];
                java.util.Arrays.fill(padded, pad);
                System.arraycopy(stream, from, padded, 16, left);
                int answered;
                try {
                    answered = reader.endOfAnswer(padded, 16, left);
                } catch (Throwable thrown) {
                    return new Reading(ends, thrown);
                }
                if (answered < -1 || answered > left) {
                    // Deliberately NOT recorded as a refusal. A Reading's
                    // failure is what the implementation chose to throw, and a
                    // refusal is often the right answer to a hostile block - so
                    // putting a breach there would hide it among the legitimate
                    // ones and make the count of refusals a lie. The contract's
                    // own control found that: three mutants were caught and this
                    // one passed, because its breach was being filed as a
                    // refusal both times and the two readings therefore agreed.
                    throw new AssertionError("answered " + answered + " for a block of "
                            + left + " - outside the range the interface allows, so a relay "
                            + "would forward bytes it has not got\n  stream: " + hex(stream));
                }
                if (answered < 0) {
                    break;
                }
                ends.add(from + answered);
                reader.reset();
                from += answered;
                left -= answered;
            }
            at += size;
        }
        return new Reading(ends, null);
    }

    /**
     * Puts one stream through every question above.
     *
     * @return what the implementation did, for a test that wants to report it
     * @throws AssertionError when an answer differs by chunking, or a reading
     *         goes outside its window
     */
    public static Reading check(String what, Supplier<AnswerBoundary> boundary, byte[] stream) {
        return withinTheBudget(what, stream, () -> checkNow(what, boundary, stream));
    }

    /**
     * Runs a reading on a thread of its own and gives up on it.
     *
     * <p>Question 3 cannot be answered from inside the walker's own loop. The
     * step budget below catches a cursor that stops advancing <b>between</b>
     * calls, which is the shape these four implementations have - but a
     * {@code while} whose condition the body never touches never returns at
     * all, and no counter outside it is ever reached. That is not theoretical:
     * the contract's own control hung this harness the first time it ran.
     *
     * <p>So the reading gets a daemon thread and a deadline. A thread spinning
     * in a tight loop cannot be interrupted - {@code interrupt} sets a flag
     * nobody reads - so it is abandoned rather than stopped, and the JVM ends
     * it on exit. Leaking a thread is the right trade for a test that has just
     * found a hang: the alternative is a build that never finishes.
     */
    private static Reading withinTheBudget(String what, byte[] stream,
            Supplier<Reading> reading) {
        java.util.concurrent.Future<Object> pending = worker.submit(() -> {
            try {
                return (Object) reading.get();
            } catch (Throwable thrown) {
                return (Object) thrown;
            }
        });
        Object result;
        try {
            result = pending.get(DEADLINE_MILLIS, java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.TimeoutException outOfTime) {
            pending.cancel(true);
            giveUpOnTheWorker();
            throw new AssertionError(what + " did not finish within " + DEADLINE_MILLIS
                    + "ms on this stream - a walker that does not return takes the "
                    + "thread with it, which is worse than a crash: a crash names a "
                    + "connection.\n  stream: " + hex(stream));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new AssertionError("interrupted while reading " + what);
        } catch (java.util.concurrent.ExecutionException impossible) {
            result = impossible.getCause();
        }
        if (result instanceof AssertionError broken) {
            throw broken;
        }
        if (result instanceof Throwable thrown) {
            throw new AssertionError(what + " broke the harness on " + hex(stream), thrown);
        }
        return (Reading) result;
    }

    private static Reading checkNow(String what, Supplier<AnswerBoundary> boundary,
            byte[] stream) {
        Reading whole = read(boundary, stream, new int[] {Integer.MAX_VALUE}, (byte) 0x00);
        Reading otherPad = read(boundary, stream, new int[] {Integer.MAX_VALUE}, (byte) 0xa5);
        agree(what, "the padding around the block", whole, otherPad, stream);

        Reading oneByteAtATime = read(boundary, stream, new int[] {1}, (byte) 0x00);
        agree(what, "one byte at a time", whole, oneByteAtATime, stream);

        // Chunkings drawn from the stream itself, so a failing case is
        // reproducible from the bytes alone and needs no seed carried with it.
        int[][] shapes = {
            {3}, {5, 1}, {7, 2, 13}, {1, 1, 250}, {64, 1}, {2, 3, 5, 7, 11},
        };
        for (int[] shape : shapes) {
            agree(what, "chunks " + java.util.Arrays.toString(shape),
                    whole, read(boundary, stream, shape, (byte) 0x00), stream);
        }
        return whole;
    }

    private static void agree(String what, String how, Reading a, Reading b, byte[] stream) {
        if (a.answerEnds().equals(b.answerEnds()) && sameFailure(a.failure(), b.failure())) {
            return;
        }
        throw new AssertionError(what + " reads this stream differently depending on "
                + how + "\n  whole: " + a.describe()
                + "\n  " + how + ": " + b.describe()
                + "\n  stream: " + hex(stream));
    }

    private static boolean sameFailure(Throwable a, Throwable b) {
        if (a == null || b == null) {
            return a == b;
        }
        return a.getClass().equals(b.getClass());
    }

    /** The whole stream as hex, so a failure carries its own reproduction. */
    public static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16))
               .append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }

    /** The other direction, for a corpus entry written down as hex. */
    public static byte[] unhex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
