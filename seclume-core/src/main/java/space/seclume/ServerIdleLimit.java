package space.seclume;

import java.sql.SQLException;
import java.time.Duration;

/**
 * How long the server lets this session sit idle before it closes it - the
 * cause behind most "Communications link failure" and "Got minus one from a
 * read call" in a pooled application.
 *
 * <p>A pool keeps connections idle by design, and a server with an idle limit
 * closes them by design: MySQL's {@code wait_timeout}, PostgreSQL's
 * {@code idle_session_timeout}, an Oracle profile's {@code IDLE_TIME}. The
 * usual remedy is a keepalive or a lifetime set by hand below that limit, in a
 * second place, and remembered when the limit changes. A pool asks this once,
 * at its first connection, and keeps its idle connections alive below the
 * limit on its own.
 */
public interface ServerIdleLimit {

    /**
     * The idle limit of this session, asked of the server now - or
     * {@code null} when the server has none, or none this user may see.
     * SQL Server has none.
     */
    Duration idleLimit() throws SQLException;
}
