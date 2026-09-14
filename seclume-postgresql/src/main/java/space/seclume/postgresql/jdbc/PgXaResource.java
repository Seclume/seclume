package space.seclume.postgresql.jdbc;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import javax.transaction.xa.Xid;

import space.seclume.internal.jdbc.AbstractXaResource;
import space.seclume.internal.jdbc.XidText;

/**
 * Two-phase commit for PostgreSQL.
 *
 * <p>PostgreSQL does this in SQL and not in the protocol:
 * {@code PREPARE TRANSACTION 'name'} writes the open transaction to disk under
 * a name and ends it on this connection; {@code COMMIT PREPARED 'name'} or
 * {@code ROLLBACK PREPARED 'name'} finishes it later - from any connection,
 * and after a crash of the application, which is the whole point of the
 * exercise.
 *
 * <p>The name is the {@link Xid} in text; see {@link XidText} for why it is
 * hexadecimal.
 *
 * <p><b>One thing has to be set on the server:</b> {@code max_prepared_
 * transactions} is zero by default, and with it {@code PREPARE TRANSACTION}
 * fails. That is not this driver's doing, and the error says so plainly rather
 * than hiding behind a bare {@code XAER_RMERR}.
 */
final class PgXaResource extends AbstractXaResource {

    private final PgConnection session;

    PgXaResource(PgConnection session) {
        super(session);
        this.session = session;
    }

    @Override
    protected void begin(Xid xid) throws SQLException {
        session.setAutoCommit(false);
    }

    @Override
    protected void finish(Xid xid) {
        // Nothing: the transaction stays open on this connection until prepare
        // or rollback. PostgreSQL has no notion of suspending one.
    }

    @Override
    protected void prepareBranch(Xid xid) throws SQLException {
        run("prepare transaction " + quoted(XidText.of(xid)));
        session.setAutoCommit(true);
    }

    @Override
    protected void commitOnePhase(Xid xid) throws SQLException {
        session.commit();
        session.setAutoCommit(true);
    }

    @Override
    protected void commitPrepared(Xid xid) throws SQLException {
        run("commit prepared " + quoted(XidText.of(xid)));
    }

    @Override
    protected void rollbackBranch(Xid xid, boolean open) throws SQLException {
        if (open) {
            session.rollback();
            session.setAutoCommit(true);
            return;
        }
        run("rollback prepared " + quoted(XidText.of(xid)));
    }

    @Override
    protected Xid[] scan() throws SQLException {
        List<Xid> found = new ArrayList<>();
        try (Statement statement = session.createStatement();
             ResultSet rows = statement.executeQuery("select gid from pg_prepared_xacts")) {
            while (rows.next()) {
                Xid xid = XidText.parse(rows.getString(1));
                if (xid != null) {
                    // Names this driver did not write belong to somebody else;
                    // handing them out would invite a foreign transaction to be
                    // rolled back by mistake.
                    found.add(xid);
                }
            }
        }
        return found.toArray(new Xid[0]);
    }

    /**
     * 55000, {@code object_not_in_prerequisite_state} - matched by state and
     * not by text, because the text arrives in the server's language.
     */
    @Override
    protected boolean twoPhaseDisabled(SQLException cause) {
        return "55000".equals(cause.getSQLState());
    }

    @Override
    protected String twoPhaseHint() {
        return "the server refuses prepared transactions: max_prepared_transactions is 0. "
                + "Set it to at least the number of concurrent distributed transactions "
                + "and restart the server - without it there is no two-phase commit.";
    }
}
