package space.seclume.internal.jdbc;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import javax.transaction.xa.XAException;
import javax.transaction.xa.XAResource;
import javax.transaction.xa.Xid;

/**
 * What all four databases have in common about two-phase commit.
 *
 * <p>The protocol on the wire could hardly be more different - PostgreSQL uses
 * {@code PREPARE TRANSACTION}, MySQL an {@code XA} statement family, Oracle a
 * package, SQL Server a stored procedure - but the bookkeeping above it is the
 * same everywhere: which branch is open on this connection, which call is
 * allowed when, and how a {@link SQLException} turns into an
 * {@link XAException} that says something useful.
 *
 * <p>So that part lives here once. A driver says what the four steps mean on
 * its server and nothing else; the state machine, the checks and the error
 * texts are shared, which is the only way they stay identical across drivers.
 */
public abstract class AbstractXaResource implements XAResource {

    /** The session this branch runs on. */
    protected final Connection connection;

    private Xid active;
    private int timeoutSeconds;

    protected AbstractXaResource(Connection connection) {
        this.connection = connection;
    }

    /** Opens the branch on the server - the transaction starts here. */
    protected abstract void begin(Xid xid) throws SQLException;

    /** Ends the work on the branch; nothing is decided yet. */
    protected abstract void finish(Xid xid) throws SQLException;

    /** Writes the branch to disk so it survives a crash. */
    protected abstract void prepareBranch(Xid xid) throws SQLException;

    /** Finishes a branch that was prepared - possibly from another session. */
    protected abstract void commitPrepared(Xid xid) throws SQLException;

    /** Commits without a prepare, for the single-database case. */
    protected abstract void commitOnePhase(Xid xid) throws SQLException;

    /**
     * Discards the branch.
     *
     * @param open whether it is still the branch of this connection - a
     *             prepared one is rolled back by name instead
     */
    protected abstract void rollbackBranch(Xid xid, boolean open) throws SQLException;

    /** Everything prepared and unfinished on this server. */
    protected abstract Xid[] scan() throws SQLException;

    /**
     * Whether the server has two-phase commit switched off rather than having
     * refused this particular transaction. Some do by default, and then saying
     * so is worth far more than the server's own wording.
     */
    protected boolean twoPhaseDisabled(SQLException cause) {
        return false;
    }

    /** What to say when it is off - a driver names the setting to change. */
    protected String twoPhaseHint() {
        return "the server refuses prepared transactions";
    }

    @Override
    public final void start(Xid xid, int flags) throws XAException {
        if (flags == TMRESUME || flags == TMJOIN) {
            // The same branch again on the same connection - already open.
            active = xid;
            return;
        }
        if (active != null) {
            throw error(XAException.XAER_PROTO,
                    "this connection is already in a distributed transaction");
        }
        try {
            begin(xid);
        } catch (SQLException e) {
            throw failed(XAException.XAER_RMERR, "could not open the transaction", e);
        }
        active = xid;
    }

    @Override
    public final void end(Xid xid, int flags) throws XAException {
        require(xid);
        try {
            finish(xid);
        } catch (SQLException e) {
            throw failed(XAException.XAER_RMERR, "could not end the transaction", e);
        }
    }

    @Override
    public final int prepare(Xid xid) throws XAException {
        require(xid);
        try {
            prepareBranch(xid);
            active = null;
            return XA_OK;
        } catch (SQLException e) {
            if (twoPhaseDisabled(e)) {
                throw error(XAException.XAER_RMERR, twoPhaseHint());
            }
            throw failed(XAException.XAER_RMERR, "the prepare failed", e);
        }
    }

    @Override
    public final void commit(Xid xid, boolean onePhase) throws XAException {
        try {
            if (onePhase) {
                require(xid);
                commitOnePhase(xid);
                active = null;
                return;
            }
            commitPrepared(xid);
        } catch (SQLException e) {
            throw failed(XAException.XAER_RMERR, "the commit failed", e);
        }
    }

    @Override
    public final void rollback(Xid xid) throws XAException {
        boolean open = active != null && sameXid(active, xid);
        try {
            rollbackBranch(xid, open);
            if (open) {
                active = null;
            }
        } catch (SQLException e) {
            throw failed(XAException.XAER_RMERR, "the rollback failed", e);
        }
    }

    /**
     * What is still lying around prepared - after a crash of the application,
     * this is how the transaction manager learns what it has to finish.
     */
    @Override
    public final Xid[] recover(int flag) throws XAException {
        if ((flag & (TMSTARTRSCAN | TMENDRSCAN)) == 0 && flag != TMNOFLAGS) {
            return new Xid[0];
        }
        if (flag == TMENDRSCAN) {
            return new Xid[0];                   // the scan was one call, it is over
        }
        try {
            return scan();
        } catch (SQLException e) {
            throw failed(XAException.XAER_RMERR, "could not list the prepared transactions", e);
        }
    }

    /**
     * None of these four servers keeps heuristic decisions: a prepared branch
     * is either finished or still there. So there is nothing to forget, and
     * saying so is more honest than pretending.
     */
    @Override
    public void forget(Xid xid) throws XAException {
        throw error(XAException.XAER_NOTA,
                "this server has no heuristic decisions, so there is nothing to forget - "
                + "an unfinished branch shows up in recover() and is ended with commit or "
                + "rollback");
    }

    /**
     * Only the very same connection.
     *
     * <p>Two sessions on one server could in principle share a branch, but all
     * four of these servers tie the open transaction to the session, so
     * joining them would be a promise this could not keep.
     */
    @Override
    public boolean isSameRM(XAResource other) {
        return this == other;
    }

    @Override
    public final int getTransactionTimeout() {
        return timeoutSeconds;
    }

    @Override
    public final boolean setTransactionTimeout(int seconds) {
        this.timeoutSeconds = seconds;
        return false;                            // not passed on to the server
    }

    /** The branch that is open on this connection, or {@code null}. */
    protected final Xid active() {
        return active;
    }

    /** One statement, no result - what most of these steps come down to. */
    protected final void run(String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    /** A name in single quotes, doubled inside - never a value from a user. */
    protected static String quoted(String name) {
        return "'" + name.replace("'", "''") + "'";
    }

    private void require(Xid xid) throws XAException {
        if (active == null || !sameXid(active, xid)) {
            throw error(XAException.XAER_NOTA, "this connection is not in that transaction");
        }
    }

    private static boolean sameXid(Xid one, Xid other) {
        return XidText.of(one).equals(XidText.of(other));
    }

    /** An XA error that keeps the cause - a manager logs one, a human reads both. */
    protected static XAException failed(int code, String what, SQLException cause) {
        XAException failure = error(code, what + ": " + cause.getMessage());
        failure.initCause(cause);
        return failure;
    }

    protected static XAException error(int code, String message) {
        XAException failure = new XAException(message);
        failure.errorCode = code;
        return failure;
    }
}
