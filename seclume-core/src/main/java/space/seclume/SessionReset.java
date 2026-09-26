package space.seclume;

import java.sql.SQLException;

/**
 * State a connection carries beyond its transaction - and putting it back
 * before the next borrower gets the connection.
 *
 * <p><b>The leak this closes.</b> A pool resets what JDBC knows about: the
 * open transaction, auto-commit, read-only, the isolation level. What a
 * statement set stays: {@code SET app.tenant_id = 42} instead of
 * {@code set_config(..., true)}, a {@code search_path}, a temporary table, a
 * MySQL user variable, a session-level advisory lock, an Oracle package
 * variable or client identifier. The next request on that connection runs
 * with it - the most common way row-level security breaks in practice, since
 * the tenant of one request becomes the tenant of the next.
 *
 * <p><b>How.</b> The four drivers note every statement that sets such state -
 * they read each statement anyway - and the pool asks on return: only a
 * connection that had one is reset, so the ordinary return costs nothing. The
 * reset is the server's own: {@code RESET ALL}, {@code DISCARD TEMP} and their
 * kind on PostgreSQL, {@code COM_RESET_CONNECTION} on MySQL, the
 * RESETCONNECTION bit on the next TDS request for SQL Server (no round trip
 * of its own), package state and client identifiers on Oracle. What cannot be
 * put back - an Oracle {@code ALTER SESSION} - makes {@link #resetSessionState}
 * say so, and the pool closes that connection instead of lending it again.
 *
 * <p>Noting errs towards resetting: a statement that only looks like it sets
 * something costs one reset, a statement that sets something unnoticed would
 * cost the next borrower their tenant.
 */
public interface SessionReset {

    /** Whether a statement since the last reset set state beyond the transaction. */
    boolean sessionStateChanged();

    /**
     * Puts the session back to how the login left it, as far as the server
     * allows, and forgets what was noted.
     *
     * <p>Only between transactions: call it with auto-commit on and nothing
     * open, as a pool does after its own rollback.
     *
     * @return false when something set cannot be put back - the connection
     *         should then not be lent again
     */
    boolean resetSessionState() throws SQLException;
}
