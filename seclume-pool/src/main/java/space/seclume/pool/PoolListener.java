package space.seclume.pool;

/**
 * What a pool reports as it happens - durations for timers and histograms,
 * the one kind of number its statistics cannot give: how long a borrower
 * waited, how long a connection was held, how long opening one took.
 *
 * <p>No dependency: the Spring Boot starter turns these into Micrometer
 * timers, and anything else can do the same. Without a listener the pool
 * reads no extra clock and calls nothing. A listener is called on the
 * borrowing and returning threads, on the hot path - it must be quick and
 * must not throw.
 *
 * <p>Never a statement, a value or a credential: durations and events only.
 */
public interface PoolListener {

    /** A connection was handed out after {@code waitedNanos}, opening it included. */
    default void acquired(long waitedNanos) {
    }

    /** A connection came back after being held for {@code heldNanos}. */
    default void released(long heldNanos) {
    }

    /** A new connection was opened - login included - in {@code tookNanos}. */
    default void opened(long tookNanos) {
    }

    /**
     * The reset of a returned connection was refused or broke, and the
     * connection was closed instead of lent again.
     */
    default void resetRefused() {
    }
}
