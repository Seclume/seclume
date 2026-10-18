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
 * and SQL Server the RESETCONNECTION bit on the next request. Oracle has no
 * complete reset; its driver logs off and logs in again on the same
 * connection, which gives a new session, and where it cannot (a Kerberos or
 * Windows login) reports that, so the pool retires that session.
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

    /**
     * Whether the reset {@link #resetSessionState} sent still owes its answer.
     * A driver that sends it and reads the answer before the next statement
     * (PostgreSQL's {@code DISCARD ALL}, MySQL's {@code COM_RESET_CONNECTION})
     * says yes until {@link #settleReset} has read it; one that resets on the
     * next request itself, or waits at once, never does.
     */
    default boolean resetOwed() {
        return false;
    }

    /**
     * Reads the answer to the reset sent at the return, waiting for it. A
     * pool calls this before it lends the connection again - when it takes it
     * out, by which time the round trip has usually passed while the
     * connection waited in the pool (see {@link #resetAnswered}).
     *
     * @throws SQLException when the reset was refused or the connection broke:
     *                      the session must then not be lent again
     */
    default void settleReset() throws SQLException {
    }

    /**
     * Whether the answer {@link #resetOwed} speaks of has arrived, so that
     * {@link #settleReset} reads it without waiting - looked at without
     * reading. A hint: a pool takes such a connection before one it would
     * wait a round trip for. {@code true} when nothing is owed, and when the
     * driver cannot tell.
     */
    default boolean resetAnswered() {
        return true;
    }
}
