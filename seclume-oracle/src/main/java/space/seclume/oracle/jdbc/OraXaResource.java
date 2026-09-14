package space.seclume.oracle.jdbc;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import javax.transaction.xa.Xid;

import space.seclume.internal.jdbc.AbstractXaResource;
import space.seclume.internal.jdbc.XidText;

/**
 * Two-phase commit for Oracle.
 *
 * <p>Oracle keeps its XA calls in a package, {@code DBMS_XA}, and every one of
 * them is a function returning a code rather than something that raises by
 * itself. So each step is one anonymous block that calls the function and
 * raises when the code is not {@code XA_OK} - the driver would otherwise
 * happily walk past a branch that was never started.
 *
 * <p>Two things the server insists on, both found by trying rather than by
 * reading:
 * <ul>
 *   <li>The session must not be in autocommit. Oracle answers {@code ORA-02089}
 *       otherwise, and this class switches it off in {@code start} so that
 *       nobody has to know that.</li>
 *   <li>Recovery does not come from the package. {@code DBMS_XA.XA_RECOVER}
 *       cannot be selected from, so the branches are read from
 *       {@code DBA_PENDING_TRANSACTIONS} - which the account needs to be
 *       allowed to see.</li>
 * </ul>
 */
final class OraXaResource extends AbstractXaResource {

    private final OraConnection session;

    OraXaResource(OraConnection session) {
        super(session);
        this.session = session;
    }

    @Override
    protected void begin(Xid xid) throws SQLException {
        // ORA-02089: inside an XA branch the session may not commit on its
        // own, and autocommit is exactly that.
        session.setAutoCommit(false);
        call("dbms_xa.xa_start(" + xid(xid) + ", dbms_xa.tmnoflags)");
    }

    @Override
    protected void finish(Xid xid) throws SQLException {
        call("dbms_xa.xa_end(" + xid(xid) + ", dbms_xa.tmsuccess)");
    }

    @Override
    protected void prepareBranch(Xid xid) throws SQLException {
        // XA_RDONLY (3) means the branch touched nothing and is already done;
        // it is a success, not a failure.
        call("dbms_xa.xa_prepare(" + xid(xid) + ")", "3");
    }

    @Override
    protected void commitOnePhase(Xid xid) throws SQLException {
        call("dbms_xa.xa_commit(" + xid(xid) + ", true)");
    }

    @Override
    protected void commitPrepared(Xid xid) throws SQLException {
        call("dbms_xa.xa_commit(" + xid(xid) + ", false)");
    }

    @Override
    protected void rollbackBranch(Xid xid, boolean open) throws SQLException {
        call("dbms_xa.xa_rollback(" + xid(xid) + ")");
    }

    @Override
    protected Xid[] scan() throws SQLException {
        List<Xid> found = new ArrayList<>();
        try (Statement statement = session.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select formatid, rawtohex(globalid), rawtohex(branchid) "
                     + "from dba_pending_transactions")) {
            while (rows.next()) {
                byte[] global = unhex(rows.getString(2)); // seclume-allow: a transaction id, not a secret
                byte[] branch = unhex(rows.getString(3)); // seclume-allow: a transaction id, not a secret
                if (global != null && branch != null) {
                    found.add(new XidText.Recovered(rows.getInt(1), global, branch));
                }
            }
        }
        return found.toArray(new Xid[0]);
    }

    /** One DBMS_XA call; anything but {@code XA_OK} comes back as an error. */
    private void call(String function) throws SQLException {
        call(function, null);
    }

    /**
     * @param alsoGood a second return code that counts as success, or
     *                 {@code null} - {@code XA_RDONLY} is the only one
     */
    private void call(String function, String alsoGood) throws SQLException {
        String good = alsoGood == null ? "dbms_xa.xa_ok"
                : "dbms_xa.xa_ok, " + alsoGood;
        run("declare r pls_integer; begin r := " + function + "; "
                + "if r not in (" + good + ") then "
                + "raise_application_error(-20099, 'DBMS_XA returned ' || r); end if; end;");
    }

    /** The id as Oracle wants it: a number and two RAWs. */
    private static String xid(Xid xid) {
        StringBuilder text = new StringBuilder(80); // seclume-allow: a transaction id, not a secret
        text.append("dbms_xa_xid(").append(xid.getFormatId()).append(", ");
        appendRaw(text, xid.getGlobalTransactionId());
        text.append(", ");
        appendRaw(text, xid.getBranchQualifier());
        text.append(')');
        return text.toString();
    }

    private static void appendRaw(StringBuilder text, byte[] bytes) {
        text.append("hextoraw('");
        if (bytes != null) {
            for (byte value : bytes) {
                text.append(Character.forDigit((value >> 4) & 0xf, 16));
                text.append(Character.forDigit(value & 0xf, 16));
            }
        }
        text.append("')");
    }

    private static byte[] unhex(String text) {
        if (text == null || text.length() % 2 != 0) {
            return null;
        }
        byte[] bytes = new byte[text.length() / 2]; // seclume-allow: a transaction id, not a secret
        for (int i = 0; i < bytes.length; i++) {
            int high = Character.digit(text.charAt(i * 2), 16);
            int low = Character.digit(text.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                return null;
            }
            bytes[i] = (byte) ((high << 4) | low);
        }
        return bytes;
    }
}
