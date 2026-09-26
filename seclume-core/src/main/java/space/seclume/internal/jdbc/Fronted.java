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
}
