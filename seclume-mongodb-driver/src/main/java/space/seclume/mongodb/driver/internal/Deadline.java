package space.seclume.mongodb.driver.internal;

import java.util.concurrent.TimeUnit;

import com.mongodb.MongoOperationTimeoutException;

/**
 * {@code timeoutMS}: one limit for a whole operation - selecting a server,
 * taking a connection, every command and every retry of it - as the
 * client-side operations timeout specification (source/client-side-
 * operations-timeout) describes it.
 *
 * <p>Per thread, because an operation runs on the thread that called it, and
 * nested: an operation inside another (the find an aggregate with
 * {@code $out} reads its results with, the commit of withTransaction) keeps
 * the earlier of the two ends.
 */
public final class Deadline {

    private static final ThreadLocal<Long> END = new ThreadLocal<>();
    /** Set for a cursor whose timeout applies per batch: its first command gets no maxTimeMS. */
    private static final ThreadLocal<Boolean> PER_BATCH = new ThreadLocal<>();

    private Deadline() {
    }

    /** What {@link #enter} returns: closing it ends the scope. */
    public static class Scope implements AutoCloseable {
        private final Long before;
        private final boolean entered;

        private Scope(Long before, boolean entered) {
            this.before = before;
            this.entered = entered;
        }

        @Override
        public void close() {
            if (!entered) {
                return;
            }
            if (before == null) {
                END.remove();
            } else {
                END.set(before);
            }
        }
    }

    /**
     * An operation with {@code timeoutMillis}: {@code null} for none set, 0
     * for none at all (which also lifts an outer one, as timeoutMS=0 does).
     */
    public static Scope enter(Long timeoutMillis) {
        if (timeoutMillis == null) {
            return new Scope(null, false);
        }
        Long before = END.get();
        if (timeoutMillis == 0) {
            END.remove();
            return new Scope(before, true);
        }
        long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        END.set(before == null ? end : Math.min(before, end));
        return new Scope(before, true);
    }

    /**
     * A cursor's first command when its timeout applies to each batch
     * (TimeoutMode.ITERATION): bounded, but without maxTimeMS - on a find
     * the server counts that over all batches of the cursor.
     */
    public static Scope perBatch(Long timeoutMillis) {
        Scope inner = enter(timeoutMillis);
        Boolean before = PER_BATCH.get();
        PER_BATCH.set(Boolean.TRUE);
        return new Scope(null, false) {
            @Override
            public void close() {
                if (before == null) {
                    PER_BATCH.remove();
                } else {
                    PER_BATCH.set(before);
                }
                inner.close();
            }
        };
    }

    /** Whether commands now get a maxTimeMS from the deadline. */
    public static boolean serverLimit() {
        return active() && !Boolean.TRUE.equals(PER_BATCH.get());
    }

    /** An end already known - a cursor's lifetime - entered again for one of its commands. */
    public static Scope at(long endNanos) {
        Long before = END.get();
        END.set(before == null ? endNanos : Math.min(before, endNanos));
        return new Scope(before, true);
    }

    public static boolean active() {
        return END.get() != null;
    }

    /** The end of the current operation, or null. */
    public static Long end() {
        return END.get();
    }

    /** Milliseconds left, at least 0; {@link Long#MAX_VALUE} with no deadline. */
    public static long remainingMillis() {
        Long end = END.get();
        if (end == null) {
            return Long.MAX_VALUE;
        }
        return Math.max(0, TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime()));
    }

    /** {@code bound}, or less if the operation ends sooner. */
    public static long bounded(long bound) {
        return Math.min(bound, remainingMillis());
    }

    /** Throws when the operation has no time left, before {@code doing} is begun. */
    public static void check(String doing) {
        Long end = END.get();
        if (end != null && end - System.nanoTime() <= 0) {
            throw expired(doing, null);
        }
    }

    public static MongoOperationTimeoutException expired(String doing, Throwable cause) {
        return new MongoOperationTimeoutException("the operation's timeout (timeoutMS) "
                + "expired while " + doing, cause);
    }
}
