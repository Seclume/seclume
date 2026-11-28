package space.seclume;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;

/**
 * The session context of one borrow, named by the caller rather than read
 * off the thread.
 *
 * <p>A pool's session-context supplier is asked on the borrowing thread. A
 * reactive application keeps its tenant in the Reactor context, and its
 * borrows run on whichever thread subscribes - an event loop when a
 * connection is free, a thread of the pool's when it has to wait. The same
 * request then ran with its tenant at low load and without it under load.
 * A borrow made inside {@link #with} gets exactly the map given, and the
 * supplier is not asked.
 *
 * <p>Bound for the duration of the call on the calling thread, and only
 * there; a borrow the call hands to another thread does not see it.
 */
public final class BorrowContext {

    private static final ThreadLocal<Map<String, String>> NAMED = new ThreadLocal<>();

    private BorrowContext() {
    }

    /**
     * Runs {@code borrow} with {@code context} as the session context of every
     * borrow it makes on this thread; an empty map means none.
     */
    public static <T> T with(Map<String, String> context, Callable<T> borrow) throws Exception {
        Map<String, String> named = Map.copyOf(Objects.requireNonNull(context, "context"));
        Map<String, String> outer = NAMED.get();
        NAMED.set(named);
        try {
            return borrow.call();
        } finally {
            if (outer == null) {
                NAMED.remove();
            } else {
                NAMED.set(outer);
            }
        }
    }

    /** The context named for the borrow under way on this thread, or null for none named. */
    public static Map<String, String> named() {
        return NAMED.get();
    }
}
