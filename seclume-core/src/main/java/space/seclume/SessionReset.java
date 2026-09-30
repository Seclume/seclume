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
 * <p>The pool resets every used session, regardless of SQL text. Functions and
 * stored procedures can change session state without the driver noticing.
 * PostgreSQL uses {@code DISCARD ALL}, MySQL {@code COM_RESET_CONNECTION},
 * and SQL Server the RESETCONNECTION bit on the next request. Oracle reports
 * that a complete reset is unavailable, so the pool retires that session.
 * Prepared statement caches must be invalidated along with server state.
 *
 * <p>This boundary is the return of a borrow, not migration. Detaching and
 * adopting a live connection must preserve its transaction and session state.
 */
public interface SessionReset {

    /**
     * Whether the SQL tracker noticed session state changes. A false result is
     * not proof of a clean session and must never be used to skip a pool reset.
     */
    boolean sessionStateChanged();

    /**
     * Resets the session unconditionally and forgets what was noted. Returns
     * false if the driver cannot fully restore the session for another borrower.
     *
     * <p>Only between transactions: call it with auto-commit on and nothing
     * open, as a pool does after its own rollback.
     *
     * @return false when something set cannot be put back - the connection
     *         should then not be lent again
     */
    boolean resetSessionState() throws SQLException;
}
