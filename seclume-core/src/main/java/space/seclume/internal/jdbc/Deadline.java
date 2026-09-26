package space.seclume.internal.jdbc;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A statement's time limit, and the thread that enforces it.
 *
 * <p>{@code setQueryTimeout} is the one JDBC call that cannot be implemented
 * by the thread it is set on: that thread is inside a blocking read, waiting
 * for the answer whose lateness is the whole problem. Somebody else has to
 * notice the time and reach the connection - which is exactly what
 * {@code cancel()} is for, and why this arrived only once all four drivers
 * could cancel.
 *
 * <p><b>Every driver does the same three things</b> around a statement it
 * runs, so they are here rather than four times over: start a timer, stop it
 * when the answer comes, and - if the timer won already - turn whatever the
 * cancellation produced into a {@link java.sql.SQLTimeoutException}. That last
 * one is not decoration. The four protocols report a cancelled statement
 * differently, and one of them does not report it at all, so a caller told
 * only "57014" or "HY008" has to know which database it is talking to in
 * order to know its deadline expired.
 *
 * <p><b>The zero case costs nothing</b>, which matters because it is nearly
 * every statement ever run: no timeout means {@link #NONE}, a shared instance
 * that starts no timer, allocates nothing and has an empty {@code close()}.
 * The scheduler itself is built on first use and never if no application sets
 * a timeout.
 *
 * <p>The race is the same one {@code cancel()} has and is not made worse here:
 * a deadline can fire just as the answer arrives, and the statement then fails
 * with a timeout having very nearly succeeded. It is narrowed by the drivers
 * refusing to send a cancellation when no answer is outstanding, and what
 * remains cannot be closed from the client.
 */
public final class Deadline implements AutoCloseable {

    /** What to do when the time is up - the driver's own cancellation. */
    @FunctionalInterface
    public interface Stop {
        void now() throws Exception;
    }

    /** No limit: the shared instance every statement without a timeout uses. */
    public static final Deadline NONE = new Deadline();

    /**
     * One thread for every deadline in the process.
     *
     * <p>It does nothing but wait, and what it runs is a cancellation - which
     * on three of the four drivers is a connection being opened, so it can
     * take a moment. A second deadline expiring in that moment waits behind
     * it, which is why this is a scheduler rather than a timer, and why the
     * thread is not the one that will carry the work.
     *
     * <p>A daemon, deliberately: a pending timeout must never be the reason a
     * JVM does not exit.
     */
    private static final class Scheduler {
        private static final ScheduledExecutorService SERVICE =
                Executors.newSingleThreadScheduledExecutor(runnable -> {
                    Thread thread = new Thread(runnable, "seclume-deadlines");
                    thread.setDaemon(true);
                    return thread;
                });
    }

    private final ScheduledFuture<?> timer;
    private final AtomicBoolean expired;

    private Deadline() {
        this.timer = null;
        this.expired = null;
    }

    private Deadline(ScheduledFuture<?> timer, AtomicBoolean expired) {
        this.timer = timer;
        this.expired = expired;
    }

    /**
     * Starts the clock, or does not if there is no limit.
     *
     * @param seconds what {@code getQueryTimeout()} says; 0 means no limit
     * @param stop    the driver's cancellation, run on the scheduler thread
     */
    public static Deadline of(int seconds, Stop stop) {
        if (seconds <= 0) {
            return NONE;
        }
        AtomicBoolean expired = new AtomicBoolean();
        ScheduledFuture<?> timer = Scheduler.SERVICE.schedule(() -> {
            // The flag first: the statement may come back between the
            // cancellation being sent and its effect arriving, and it has to
            // find out that a deadline is why.
            expired.set(true);
            try {
                stop.now();
            } catch (Exception beyondReach) {
                // A cancellation that cannot be sent leaves the statement
                // running, and the caller finds out when it finally answers.
                // Nothing useful can be thrown from here - there is no caller
                // on this thread.
            }
        }, seconds, TimeUnit.SECONDS);
        return new Deadline(timer, expired);
    }

    /** Whether the time ran out before the answer arrived. */
    public boolean expired() {
        return expired != null && expired.get();
    }

    /**
     * What the caller should be told, given what the driver threw.
     *
     * <p>A cancelled statement arrives as whatever the protocol says - 57014,
     * HY008, ORA-01013, or on MySQL as a perfectly ordinary success with a
     * short answer. Only the client knows the cancellation was a deadline
     * rather than a person, so only the client can say
     * {@code SQLTimeoutException}, and an application's retry logic is written
     * against that and not against four vendor codes.
     *
     * @param failure what the statement threw
     * @return the same exception, or a timeout wrapping it
     */
    public java.sql.SQLException explain(java.sql.SQLException failure) {
        if (!expired()) {
            return failure;
        }
        java.sql.SQLTimeoutException timeout = new java.sql.SQLTimeoutException(
                "the statement did not finish within the query timeout and was cancelled",
                failure.getSQLState(), failure.getErrorCode());
        timeout.initCause(failure);
        return timeout;
    }

    /**
     * What to do when the statement came back <b>without</b> failing.
     *
     * <p>Not a formality, and MySQL is why. A cancelled {@code SLEEP()} there
     * returns 1 instead of 0 and the statement succeeds - so a driver that
     * only rewrites exceptions hands the caller a short answer with no
     * indication that its deadline expired, which is worse than the slow
     * query was. If the clock won, the statement did not finish in time, and
     * that is what the caller is told whatever the protocol did.
     *
     * <p>This also decides the race, and decides it the safe way: a deadline
     * that fires just as the answer arrives reports a timeout for a statement
     * that very nearly succeeded. The cancellation had already gone out by
     * then, so what came back may be part of an answer rather than all of one,
     * and a timeout is the honest description of that.
     */
    public void check() throws java.sql.SQLTimeoutException {
        if (expired()) {
            throw new java.sql.SQLTimeoutException(
                    "the statement did not finish within the query timeout and was cancelled",
                    "57014");
        }
    }

    /** Stops the clock. Harmless twice, and harmless after it has fired. */
    @Override
    public void close() {
        if (timer != null) {
            timer.cancel(false);
        }
    }
}
