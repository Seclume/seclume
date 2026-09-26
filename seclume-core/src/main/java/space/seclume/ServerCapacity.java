package space.seclume;

import java.sql.SQLException;

/**
 * How many connections the server allows, and how many it has - for the
 * question every autoscaled deployment meets as "FATAL: sorry, too many
 * clients already".
 *
 * <p>The cause is almost always arithmetic nobody did: instances times pool
 * size over the server's limit. A pool asks this once, at its first
 * connection, and says so in the log while there is still room; the
 * preflight check prints it. Where the user may not see the numbers - Oracle's
 * {@code v$} views need a grant most application users lack - they are
 * reported as unknown, not guessed.
 */
public interface ServerCapacity {

    /**
     * @param allowed the connections the server allows this kind of user,
     *                or -1 when not visible
     * @param inUse   the client connections open right now, this one
     *                included, or -1 when not visible
     */
    record Capacity(int allowed, int inUse) {

        /** Whether both numbers are known. */
        public boolean known() {
            return allowed >= 0 && inUse >= 0;
        }

        /** How many more connections fit, or -1 when unknown. */
        public int free() {
            return known() ? Math.max(0, allowed - inUse) : -1;
        }
    }

    /** Asked of the server now - one or two small queries. */
    Capacity capacity() throws SQLException;
}
