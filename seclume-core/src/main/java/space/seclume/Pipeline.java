package space.seclume;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * One round trip for a whole unit of work.
 *
 * <p>JDBC is synchronous by design: every {@code executeUpdate} sends and
 * waits. A service that writes an order and four items pays four round trips
 * it did not need - the server does the work in microseconds and the rest is
 * the network. {@code executeBatch} only helps for the <b>same</b> statement
 * with different values; four different statements cannot be bundled, because
 * each has to return its count immediately.
 *
 * <p>This block turns that one rule around, and only inside its own braces:
 *
 * {@snippet :
 * connection.setAutoCommit(false);
 * try (Pipeline unit = Pipeline.open(connection)) {
 *     insertOrder.executeUpdate();      // buffered
 *     insertItem.executeUpdate();       // buffered
 *     insertItem.executeUpdate();       // buffered
 * }                                     // one round trip for all of them
 * connection.commit();
 * }
 *
 * <p><b>No number is ever invented.</b> A buffered write answers with
 * {@link java.sql.Statement#SUCCESS_NO_INFO}, the value JDBC already uses for
 * "done, count unknown". And the moment anything really needs an answer - a
 * query, a commit, a requested count - everything buffered goes out first. The
 * block saves round trips that nobody was waiting for; it never guesses one.
 *
 * <p><b>Only inside a transaction.</b> In auto-commit each statement would
 * commit on its own, and a failure in the third would leave the first two
 * behind - a half-written unit of work is worse than a slow one. Opening the
 * block without a transaction is refused.
 *
 * <p><b>When one of them fails</b>, the exception says which one it was and
 * what became of the statements behind it. "Something in there went wrong" is
 * not something anybody can act on.
 *
 * <p>Outside the block, JDBC behaves exactly as before. There is no setting
 * that changes it globally - that would be a semantic change nobody asked for.
 *
 * <p><b>Where it saves anything.</b> PostgreSQL and MySQL bundle; Oracle and
 * SQL Server accept the block and save nothing, because their protocols answer
 * every call of their own accord. The block is allowed there so that the same
 * code runs against all four - but it is said out loud rather than implied,
 * and {@link #counts()} comes back empty where nothing was held back.
 *
 * <p>The two that bundle differ in one thing worth knowing: after a failure
 * PostgreSQL <b>skips</b> the rest of the group, MySQL <b>runs</b> it. Both
 * say which in the message of the exception.
 */
public final class Pipeline implements AutoCloseable {

    private final Pipelined connection;
    private long[] counts = new long[0]; // seclume-allow: update counts, not a secret
    private boolean closed;

    private Pipeline(Pipelined connection) {
        this.connection = connection;
    }

    /**
     * Opens the block on this connection.
     *
     * @throws SQLException if the driver does not pipeline, or the connection
     *         is in auto-commit
     */
    public static Pipeline open(Connection connection) throws SQLException {
        Pipelined pipelined = Pipelined.of(connection);
        if (pipelined == null) {
            throw new SQLException("this connection cannot pipeline - a Pipeline needs a "
                    + "seclume driver, because it is the driver that decides when a "
                    + "statement goes on the wire");
        }
        pipelined.beginPipeline();
        return new Pipeline(pipelined);
    }

    /**
     * Sends what is buffered without ending the block.
     *
     * <p>Rarely needed - the driver does it by itself whenever an answer is
     * required. Useful when a very long block should not hold more than a few
     * statements at a time.
     */
    public void flush() throws SQLException {
        connection.flushPipeline();
    }

    /**
     * The update counts of the buffered statements, in the order they were
     * written - available once the block is closed.
     */
    public long[] counts() {
        return counts.clone();
    }

    /** Sends the rest and ends the block. */
    @Override
    public void close() throws SQLException {
        if (closed) {
            return;
        }
        closed = true;
        counts = connection.endPipeline();
    }
}
