package space.seclume;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * How often a connection has waited for the server.
 *
 * <p>Every serious performance problem of a database application is a question
 * of round trips, and they are the one thing nobody can see. What gets measured
 * instead is milliseconds - and those depend on the network, on the machine, on
 * the time of day. A count does not: <b>this method used to need three round
 * trips and now needs seven</b> is a fact, reproducible on a laptop and in
 * production, and it is the same number on both.
 *
 * <p>This is why it exists as an ordinary part of the driver rather than as a
 * debugging switch. The counter costs one increment per request and can be read
 * at any time:
 *
 * <pre>
 * long before = RoundTrips.of(connection);
 * repository.save(order);
 * long spent = RoundTrips.of(connection) - before;
 * </pre>
 *
 * <p>What counts as one: everything that goes out and is waited for. A batch
 * that sends five hundred rows in two groups counts two, not five hundred -
 * which is exactly the difference the number is meant to make visible.
 */
public interface RoundTrips {

    /** How many times this connection has waited for an answer. */
    long roundTrips();

    /**
     * The count of any seclume connection - also through a pool.
     *
     * @throws SQLException if this is not a seclume connection
     */
    static long of(Connection connection) throws SQLException {
        if (connection instanceof RoundTrips counted) {
            return counted.roundTrips();
        }
        if (connection.isWrapperFor(RoundTrips.class)) {
            return connection.unwrap(RoundTrips.class).roundTrips();
        }
        throw new SQLException("this is not a seclume connection, so nobody counted: "
                + connection.getClass().getName());
    }
}
