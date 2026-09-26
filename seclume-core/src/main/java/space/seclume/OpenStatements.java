package space.seclume;

import java.sql.Statement;
import java.util.List;

/**
 * The statements a connection has handed out and nobody closed - for the
 * pool to find when the connection comes back.
 *
 * <p>An unclosed statement holds a server cursor on Oracle ({@code ORA-01000:
 * maximum open cursors exceeded} after enough of them), result memory on the
 * others, and on a pooled connection it outlives the request that forgot it.
 * A pool's leak detection works per connection - held too long - and does not
 * see these: the connection came back in time, only part of what it lent out
 * did not.
 */
public interface OpenStatements {

    /**
     * One statement still open.
     *
     * @param statement   the driver's statement
     * @param fingerprint what it last ran, without any value - null if nothing yet
     * @param createdAt   where it was made, when {@link #traceStatements} was on
     *                    at the time - null otherwise
     */
    record Opened(Statement statement, String fingerprint, StackTraceElement[] createdAt) {
    }

    /** The statements not closed, oldest first. */
    List<Opened> openStatements();

    /**
     * Whether statements made from now on record where: a stack trace per
     * statement, which is why it is off until a pool's leak detection asks.
     */
    void traceStatements(boolean on);
}
