package space.seclume;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLTimeoutException;
import java.sql.SQLTransientException;
import java.time.Duration;

/**
 * Running a transaction again when the database says it has to be run again.
 *
 * <p>A serialization failure and a deadlock are not faults. They are the
 * database saying <i>this transaction cannot stand beside the other one; do it
 * again</i> - a normal outcome of concurrency under any isolation level above
 * read-committed, and the price of not taking locks that would have been
 * slower. The transaction was rolled back completely, so running it again is
 * safe in a way that retrying almost nothing else is.
 *
 * <p><b>Nearly every application gets this wrong in the same way.</b> Either
 * the retry is not there at all, and the failure reaches a user who did
 * nothing wrong; or it is there and catches too much, so a unique-constraint
 * violation is retried five times before failing identically, and a
 * connection that is already gone is retried on itself. Both are a question of
 * classification rather than of loops, which is why the classification is the
 * part of this class worth reading.
 *
 * <pre>
 * long id = Retry.transaction(connection, tx -&gt; {
 *     try (PreparedStatement s = tx.prepareStatement(
 *             "update account set balance = balance - ? where id = ?")) {
 *         ...
 *     }
 *     return orderId;
 * });
 * </pre>
 *
 * <p>The block may run more than once, and that is the whole contract: it has
 * to be safe to run more than once. Everything inside the transaction is
 * rolled back for you; anything <b>outside</b> it - a file written, a message
 * sent, a counter incremented in memory - is not, and belongs after the call
 * rather than inside the block.
 *
 * <h2>What is retried</h2>
 *
 * <p>Only what the database itself says is transient, by SQLState:
 *
 * <ul>
 *   <li><b>class 40</b> - transaction rollback. {@code 40001} serialization
 *       failure or deadlock on PostgreSQL and MySQL, {@code 40P01}
 *       PostgreSQL's deadlock,
 *       {@code 40003} statement completion unknown. SQL Server's deadlock
 *       victim (error 1205) arrives here because the driver maps it to
 *       40001 - the server sends no SQLState of its own.</li>
 *   <li>{@link SQLTransientException}, which is the JDBC type for exactly
 *       this and which a driver may throw for reasons of its own. Oracle's
 *       {@code ORA-00060} and {@code ORA-08177} arrive this way: they keep
 *       the states ojdbc gives them (61000, 72000), which say nothing, and
 *       come as {@code SQLTransactionRollbackException}, which does.</li>
 * </ul>
 *
 * <h2>What is not, and why each one is a trap</h2>
 *
 * <ul>
 *   <li><b>class 08</b>, a connection failure. The connection is gone, so
 *       running the block on it again cannot work - it will fail identically,
 *       three times, and hide the real cause behind the last attempt. Getting
 *       a new connection is a decision for whoever owns the pool.</li>
 *   <li><b>{@code 08007}</b>, above all - the connection was lost while a
 *       COMMIT was in flight; see {@link TransactionResolutionUnknownException}.
 *       It looks like the most retryable failure of all and is the least: if
 *       the first commit was applied, running the block again does the work
 *       twice. Only the application can find out which happened.</li>
 *   <li><b>A timeout.</b> {@link SQLTimeoutException} means a deadline the
 *       caller set has already passed. Retrying spends the time again on
 *       somebody's behalf who said they did not have it.</li>
 *   <li><b>{@code 57014}</b>, cancelled. Somebody asked for this to stop.
 *       Starting it again is the opposite of what they asked.</li>
 *   <li><b>Constraint violations, syntax errors, authorisation.</b> They will
 *       happen again. A retry turns a clear failure into a slow one.</li>
 * </ul>
 *
 * <p>The list is deliberately short. A classification that guesses is worse
 * than none, because it retries the thing nobody looked at.
 */
public final class Retry {

    /** What runs inside the transaction. It may run more than once. */
    @FunctionalInterface
    public interface Work<T> {
        T run(Connection transaction) throws SQLException;
    }

    /** The same without a result. */
    @FunctionalInterface
    public interface Block {
        void run(Connection transaction) throws SQLException;
    }

    private static final int DEFAULT_ATTEMPTS = 3;
    private static final Duration DEFAULT_FIRST_WAIT = Duration.ofMillis(20);
    private static final double DEFAULT_FACTOR = 3.0;
    private static final Duration DEFAULT_CAP = Duration.ofSeconds(1);

    private final int attempts;
    private final Duration firstWait;
    private final double factor;
    private final Duration cap;

    private Retry(int attempts, Duration firstWait, double factor, Duration cap) {
        this.attempts = attempts;
        this.firstWait = firstWait;
        this.factor = factor;
        this.cap = cap;
    }

    /** Three attempts, backing off from 20ms by a factor of three, capped at a second. */
    public static Retry standard() {
        return new Retry(DEFAULT_ATTEMPTS, DEFAULT_FIRST_WAIT, DEFAULT_FACTOR, DEFAULT_CAP);
    }

    /**
     * At most this many runs of the block, including the first.
     *
     * @throws IllegalArgumentException for anything below one
     */
    public Retry upTo(int totalAttempts) {
        if (totalAttempts < 1) {
            throw new IllegalArgumentException(
                    "a transaction has to run at least once, not " + totalAttempts);
        }
        return new Retry(totalAttempts, firstWait, factor, cap);
    }

    /**
     * How long to wait between attempts.
     *
     * <p>Backing off at all is not politeness. Two transactions that deadlock
     * and both retry immediately deadlock again, in the same order, for as
     * many attempts as they have - so the wait is what breaks the symmetry,
     * and it is jittered for the same reason.
     *
     * @param first  the wait after the first failure
     * @param growth what each following wait is multiplied by
     * @param most   the longest any single wait may be
     */
    public Retry backingOff(Duration first, double growth, Duration most) {
        if (first.isNegative() || most.isNegative() || growth < 1.0) {
            throw new IllegalArgumentException(
                    "the backoff has to grow and cannot be negative");
        }
        return new Retry(attempts, first, growth, most);
    }

    /** Runs the block in a transaction, again if the database says to. */
    public static <T> T transaction(Connection connection, Work<T> work) throws SQLException {
        return standard().run(connection, work);
    }

    /**
     * The same for a block with nothing to return.
     *
     * <p>A different name and not an overload: two overloads distinguished
     * only by whether the lambda returns something are ambiguous at the call
     * site, and the compiler says so. Better a second name than a cast in
     * every caller.
     */
    public static void inTransaction(Connection connection, Block block) throws SQLException {
        standard().run(connection, transaction -> {
            block.run(transaction);
            return null;
        });
    }

    /**
     * Runs the block in a transaction, again if the database says to.
     *
     * <p>Auto-commit is turned off for the duration and put back afterwards,
     * whatever happens. That is a change to somebody else's connection and it
     * is done because the alternative is worse: a transaction helper that
     * silently commits each statement on its own would roll nothing back and
     * retry nothing correctly.
     *
     * @throws SQLException the last failure, if every attempt failed
     */
    public <T> T run(Connection connection, Work<T> work) throws SQLException {
        boolean previousAutoCommit = connection.getAutoCommit();
        if (previousAutoCommit) {
            connection.setAutoCommit(false);
        }
        try {
            return attempt(connection, work);
        } finally {
            if (previousAutoCommit) {
                try {
                    connection.setAutoCommit(true);
                } catch (SQLException broken) {
                    // The connection is already in trouble and the caller is
                    // being told about that; adding a second failure here
                    // would replace the first one.
                }
            }
        }
    }

    private <T> T attempt(Connection connection, Work<T> work) throws SQLException {
        Duration wait = firstWait;
        SQLException last = null;
        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                T answer = work.run(connection);
                connection.commit();
                return answer;
            } catch (SQLException failed) {
                last = failed;
                rollbackQuietly(connection, failed);
                if (attempt == attempts || !worthRetrying(failed)) {
                    throw failed;
                }
            }
            sleep(wait);
            wait = grow(wait);
        }
        // Unreachable: the loop either returns or throws.
        throw last;
    }

    /**
     * Whether the database said this transaction can be run again.
     *
     * <p>Public because the decision is worth reusing - a caller with its own
     * loop, a pool deciding whether to keep a connection - and because a
     * classification nobody can see is a classification nobody can check.
     */
    public static boolean worthRetrying(SQLException failure) {
        if (failure instanceof SQLTimeoutException) {
            return false;
        }
        String state = failure.getSQLState();
        if (state == null || state.length() < 2) {
            // No state at all: the driver does not know what happened, and
            // neither does this. Not retrying is the answer that cannot make
            // things worse.
            return failure instanceof SQLTransientException;
        }
        if ("57014".equals(state)) {
            return false;
        }
        // Class 40 is "transaction rollback" and it is the whole of the list.
        // The server has already undone the work; nothing is half done.
        return state.startsWith("40") || failure instanceof SQLTransientException;
    }

    /**
     * Undoing the attempt that failed.
     *
     * <p>A rollback that itself fails is not reported instead of the original
     * - it is attached to it. The first failure is the one that explains what
     * happened; the second only says the connection is now also unusable, and
     * a caller shown only that has lost the diagnosis.
     */
    private static void rollbackQuietly(Connection connection, SQLException cause) {
        try {
            connection.rollback();
        } catch (SQLException alsoBroken) {
            cause.addSuppressed(alsoBroken);
        }
    }

    private Duration grow(Duration wait) {
        Duration next = Duration.ofNanos((long) (wait.toNanos() * factor));
        return next.compareTo(cap) > 0 ? cap : next;
    }

    private static void sleep(Duration wait) throws SQLException {
        if (wait.isZero() || wait.isNegative()) {
            return;
        }
        // Jittered: two transactions that deadlocked and retry on the same
        // schedule deadlock again on the same schedule.
        long nanos = wait.toNanos();
        long jittered = nanos / 2 + (long) (Math.random() * nanos);
        try {
            Thread.sleep(jittered / 1_000_000L, (int) (jittered % 1_000_000L));
        } catch (InterruptedException stopped) {
            Thread.currentThread().interrupt();
            throw new SQLException("the retry was interrupted while waiting to try again",
                    "57014", stopped);
        }
    }
}
