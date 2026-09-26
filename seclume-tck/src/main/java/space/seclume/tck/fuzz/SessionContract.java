package space.seclume.tck.fuzz;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/**
 * What a driver must do when the server sends nonsense.
 *
 * <p>The boundary walkers answer a question about bytes. The decoders answer a
 * question about <b>values</b>, and that changes what a contract can say. "It
 * did not crash" is worthless here: a decoder that quietly returns the wrong
 * row passes every question a byte walker has to answer, and is the worse bug
 * of the two.
 *
 * <p>There is no oracle for what a hostile stream ought to decode to, and
 * building one would mean writing four protocols a second time - the mistake
 * the {@code AnswerBoundary} comment warns against. So this contract asserts
 * the part that can be asserted without one, and says plainly what it leaves
 * out.
 *
 * <h2>What is required</h2>
 *
 * <ol>
 *   <li><b>It ends.</b> A driver that waits forever for bytes that will never
 *       come has taken the caller's thread, and in a pool it has taken a
 *       connection that nothing will ever give back.
 *   <li><b>It fails as JDBC fails.</b> {@link SQLException}, or an
 *       {@link IOException} on its way to becoming one. A
 *       {@code NullPointerException} from inside a decoder is not a failure a
 *       caller can act on - it names nothing, it is not in any signature, and
 *       it will be caught by whatever generic handler is nearest and logged as
 *       a bug in the application.
 *   <li><b>It does not take the process with it.</b> A length field read off
 *       the wire and handed to an allocator is the classic way a parser is
 *       made to die, and in a server the death is not the parser's - it is
 *       every other connection's.
 *   <li><b>It does not lie about itself afterwards.</b> A session that failed
 *       mid-answer has a stream nobody can make sense of any more. Reporting
 *       itself open means a pool hands it to the next caller.
 * </ol>
 *
 * <h2>What is not required, and is therefore not claimed</h2>
 *
 * <p>That a decoded value is correct. Every case here either fails or produces
 * <em>something</em>, and this contract does not look at the something. Where
 * a value can be checked it should be checked by a round trip against the
 * encoder for the same type, which is a different test and a different day.
 */
public final class SessionContract {

    /** How long one attempt may take. Generous: some cases decode a real answer. */
    private static final long DEADLINE_MILLIS = 10_000;

    private SessionContract() {
    }

    /**
     * One thread, reused, and a new one only after a hang.
     *
     * <p>The first version started a thread per case. With ten thousand cases
     * and a thread abandoned for every one that had to be given up on, the JVM
     * ran out of native threads and died saying so: <i>failed to start the
     * native thread</i>. A watchdog that kills the run it is watching is not a
     * watchdog.
     *
     * <p>So the executor is kept and reused, and thrown away only when an
     * attempt did not come back - that thread is spinning somewhere and cannot
     * be reclaimed, but it is one thread per <b>finding</b> rather than one per
     * case, and a run with findings is a run that is about to fail anyway.
     */
    private static java.util.concurrent.ExecutorService worker =
            newWorker();

    private static java.util.concurrent.ExecutorService newWorker() {
        return java.util.concurrent.Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "session-contract");
            thread.setDaemon(true);
            return thread;
        });
    }

    private static void giveUpOnTheWorker() {
        worker.shutdownNow();
        worker = newWorker();
    }


    /** Something that drives a session and is expected to throw most of the time. */
    @FunctionalInterface
    public interface Attempt {
        void run() throws Exception;
    }

    /** How one attempt ended. */
    public enum Ending {
        /** It read the stream and returned. Nothing is claimed about what it read. */
        COMPLETED,
        /** It refused in a way a caller can act on. The ordinary outcome. */
        REFUSED,
        /** It broke the contract. */
        BREACHED
    }

    /**
     * What happened, and why it is called that.
     *
     * @param note for a breach, the sentence a report should print
     */
    public record Outcome(Ending ending, Throwable thrown, String note) {

        public String describe() {
            return thrown == null ? ending.toString()
                    : ending + " " + thrown.getClass().getSimpleName()
                      + ": " + thrown.getMessage();
        }
    }

    /**
     * Runs one attempt under the four requirements above.
     *
     * @param stillUsable asks the session whether it reports itself open, after
     *                    the attempt has failed. {@code null} where the test
     *                    has nothing to ask
     */
    public static Outcome against(Attempt attempt, java.util.function.BooleanSupplier stillUsable) {
        java.util.concurrent.atomic.AtomicReference<Thread> running =
                new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.Future<Object> pending = worker.submit(() -> {
            running.set(Thread.currentThread());
            try {
                attempt.run();
                return (Object) Ending.COMPLETED;
            } catch (Throwable thrown) {
                return (Object) thrown;
            }
        });
        Object ended;
        try {
            ended = pending.get(DEADLINE_MILLIS, TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.TimeoutException outOfTime) {
            // Where it hung, taken before the thread is interrupted: a hang
            // reported without its stack is a finding nobody can read.
            Thread stuck = running.get();
            Throwable where = null;
            if (stuck != null) {
                where = new Throwable("where the session was when the deadline passed");
                where.setStackTrace(stuck.getStackTrace());
            }
            pending.cancel(true);
            giveUpOnTheWorker();
            return new Outcome(Ending.BREACHED, where,
                    "did not return within " + DEADLINE_MILLIS + "ms - a driver waiting "
                    + "for bytes that will never come has taken the caller's thread, and "
                    + "in a pool it has taken a connection nothing will give back");
        } catch (InterruptedException interrupted) {
            // Abandon the sweep rather than record a finding. An interrupt
            // here is not the driver's doing - it is JUnit's timeout firing on
            // the test thread, and the first version treated it as a breach,
            // re-set the flag, and then reported every remaining case as
            // broken too: six thousand findings, all of them this one line.
            Thread.currentThread().interrupt();
            throw new IllegalStateException("the sweep was interrupted - this is the test "
                    + "being stopped, not the driver failing", interrupted);
        } catch (java.util.concurrent.ExecutionException impossible) {
            ended = impossible.getCause();
        }

        if (ended == Ending.COMPLETED) {
            return new Outcome(Ending.COMPLETED, null, null);
        }
        Throwable thrown = (Throwable) ended;

        if (thrown instanceof OutOfMemoryError) {
            return new Outcome(Ending.BREACHED, thrown,
                    "ran out of memory - a length off the wire reached an allocator, and in a "
                    + "server that death belongs to every other connection too");
        }
        if (thrown instanceof StackOverflowError) {
            return new Outcome(Ending.BREACHED, thrown, "recursed until the stack ran out");
        }
        if (!(thrown instanceof SQLException) && !(thrown instanceof IOException)) {
            return new Outcome(Ending.BREACHED, thrown,
                    "failed with " + thrown.getClass().getName() + ", which is not a failure a "
                    + "caller can act on: it is in no signature, it names nothing, and the "
                    + "nearest generic handler will log it as a bug in the application");
        }
        if (thrown.getMessage() == null || thrown.getMessage().isBlank()) {
            return new Outcome(Ending.BREACHED, thrown,
                    "refused without saying why");
        }
        // Only a CONNECTION failure has to leave the session unusable, and
        // the first version of this contract got that wrong: it demanded it of
        // every refusal, and then reported the driver broken for handling a
        // server's ErrorResponse correctly. A statement that the server
        // refuses is an ordinary event - the answer ends with ReadyForQuery
        // like any other, the stream is exactly where the protocol says, and a
        // session that closed itself over a syntax error would be a far worse
        // driver than one that did not.
        boolean connectionIsGone = String.valueOf(sqlState(thrown)).startsWith("08");
        if (connectionIsGone && stillUsable != null && stillUsable.getAsBoolean()) {
            return new Outcome(Ending.BREACHED, thrown,
                    "reported itself usable after the connection failed - its stream is at a "
                    + "position nobody can make sense of, and a pool would hand it on");
        }
        if (!connectionIsGone && stillUsable != null && !stillUsable.getAsBoolean()) {
            return new Outcome(Ending.BREACHED, thrown,
                    "closed itself over a refusal that was not a connection failure ("
                    + sqlState(thrown) + ") - the server said no to a statement, which is "
                    + "not a reason to throw the connection away");
        }
        return new Outcome(Ending.REFUSED, thrown, null);
    }

    /**
     * One attempt, for a coverage-guided fuzzer: throws when it breached the
     * contract, so the fuzzer keeps the input as a finding.
     */
    public static void require(Driven driven) {
        try {
            Outcome outcome = against(driven.attempt(), driven.stillUsable());
            if (outcome.ending() == Ending.BREACHED) {
                throw new AssertionError("the session contract was breached: "
                        + outcome.note() + " - " + outcome.describe(), outcome.thrown());
            }
        } finally {
            try {
                if (driven.afterwards() != null) {
                    driven.afterwards().close();
                }
            } catch (Exception ignored) {
                // a session that broke on hostile input may not close cleanly
            }
        }
    }

    /**
     * Every case a corpus generates, against one way of driving a session.
     *
     * @param drive given a script, returns an attempt that feeds it to a fresh
     *              session, and a way to ask whether that session still claims
     *              to be usable
     */
    public static void sweep(String what, Map<String, byte[]> seeds,
            Function<byte[], Driven> drive) {
        ByteCorpus corpus = ByteCorpus.from(seeds);
        Map<String, byte[]> chosen = corpus.selected();
        Map<String, String> breaches = new TreeMap<>();
        Map<String, Integer> tally = new TreeMap<>();

        chosen.forEach((name, script) -> {
            Driven driven;
            try {
                driven = drive.apply(script);
            } catch (RuntimeException couldNotEvenStart) {
                breaches.put(name, "could not be started: " + couldNotEvenStart);
                return;
            }
            Outcome outcome;
            try {
                outcome = against(driven.attempt(), driven.stillUsable());
            } finally {
                if (driven.afterwards() != null) {
                    try {
                        driven.afterwards().close();
                    } catch (Exception letGo) {
                        // Closing a session that has already failed is allowed
                        // to fail; what matters is that its buffers went back.
                    }
                }
            }
            tally.merge(outcome.ending() == Ending.REFUSED
                    ? outcome.thrown().getClass().getSimpleName()
                    : outcome.ending().toString(), 1, Integer::sum);
            if (outcome.ending() == Ending.BREACHED) {
                breaches.put(name, outcome.note()
                        + (outcome.thrown() == null ? ""
                           : "\n  " + outcome.thrown().getClass().getName()
                             + ": " + outcome.thrown().getMessage())
                        + "\n  stream: " + BoundaryContract.hex(script));
            }
        });

        System.err.println("[session fuzz " + what + "] " + chosen.size()
                + " cases, " + tally);

        if (breaches.isEmpty()) {
            return;
        }
        StringBuilder report = new StringBuilder(breaches.size() + " of "
                + chosen.size() + " cases broke the contract:\n");
        breaches.entrySet().stream().limit(6).forEach(entry ->
                report.append("\n== ").append(entry.getKey()).append('\n')
                      .append(entry.getValue()).append('\n'));
        if (breaches.size() > 6) {
            report.append("\n... and ").append(breaches.size() - 6).append(" more");
        }
        throw new AssertionError(report.toString());
    }

    private static String sqlState(Throwable thrown) {
        return thrown instanceof SQLException sql ? sql.getSQLState() : "08000";
    }

    /**
     * One session set up around a script, ready to be driven - and to be let
     * go of afterwards.
     *
     * <p><b>{@code afterwards} is not optional and not tidiness.</b> A session
     * holds its buffers in native memory, tens of kilobytes of it, and a sweep
     * builds ten thousand sessions. The first version of this sweep never
     * closed them; the first test in a class passed, the second died with the
     * JVM unable to map more memory, and surefire reported it as zero tests
     * run. Off-heap buffers are the property this whole library is built on,
     * and they are also the thing that does not get collected for you.
     *
     * @param afterwards releases what the session holds, once the outcome has
     *                   been decided
     */
    public record Driven(Attempt attempt, java.util.function.BooleanSupplier stillUsable,
                         AutoCloseable afterwards) {

        /** For a session that holds nothing worth releasing. */
        public Driven(Attempt attempt, java.util.function.BooleanSupplier stillUsable) {
            this(attempt, stillUsable, null);
        }
    }
}
