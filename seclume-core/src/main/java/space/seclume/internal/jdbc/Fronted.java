package space.seclume.internal.jdbc;

import java.sql.Connection;

/**
 * A driver connection that something stands in front of - a pool's handle
 * while it is borrowed, an XA connection's handle.
 *
 * <p>JDBC says {@code Statement.getConnection()} returns the connection that
 * made the statement, and to the application that is the handle, not the
 * connection behind it. Frameworks rely on it: Spring's {@code queryForStream}
 * gives the connection back by closing {@code statement.getConnection()}.
 * Handed the driver's own connection instead, it closed that one - the pool
 * never saw the handle come back, and every streamed query cost the pool one
 * connection for good (found 26.09.2026, by a build that waited ten seconds
 * per pool at exit). A statement or a metadata object therefore names the
 * front that was set when it was made.
 */
public interface Fronted {

    /** The handle statements made from now on name; {@code null} for the connection itself. */
    void front(Connection handle);

    /**
     * Whether a pool has this connection lent out. A pool says {@code false}
     * when the connection is back in it and {@code true} before it lends it
     * again; a connection no pool ever told is lent.
     *
     * <p>What {@code unwrap} returns is the driver's own connection, and it
     * outlived the borrow: kept by the application, its statements ran in the
     * session of whoever borrowed the connection next - another tenant's,
     * with that tenant's context and rights. Not lent, the connection refuses
     * every call that reaches the server. The pool's own checks between two
     * borrows ({@code isValid}, the owed reset's answer) are not such calls.
     */
    default void lent(boolean lent) {
    }
}
