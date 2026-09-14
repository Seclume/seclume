package space.seclume.sqlserver.jdbc;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import javax.transaction.xa.Xid;

import space.seclume.internal.jdbc.AbstractXaResource;
import space.seclume.internal.jdbc.XidText;
import space.seclume.sqlserver.tds.Tds;
import space.seclume.sqlserver.tds.TdsSession;

/**
 * Two-phase commit for SQL Server.
 *
 * <p>The most involved of the four, because it takes two layers. The branch
 * itself is opened by a stored procedure, {@code sp_xa_start} - built into the
 * server since 2017 CU16, so nothing has to be installed any more. But that
 * procedure only creates the transaction in the coordinator; the session is
 * still outside it. What puts the session in is a <b>transaction manager
 * request</b> on the wire, {@code TM_PROPAGATE_XACT}, carrying the cookie the
 * procedure handed back. The server answers with a descriptor, and from then
 * on every request quotes it in its header.
 *
 * <p>Leaving that second step out is the quiet kind of wrong: everything looks
 * like it works, the statements run - and they commit by themselves, outside
 * the branch. It cost one confused probe to find, and the test that proves it
 * checks that a rolled-back branch leaves no row behind.
 *
 * <p>And the procedures do <b>not</b> run on the working session. A session
 * that is inside the transaction and calls {@code sp_xa_commit} waits for
 * itself: the server sits in {@code PREEMPTIVE_XA_OPERATION} and never comes
 * back. So this keeps a second connection - a control connection - for every
 * XA command, and the working session only ever does the one thing it must:
 * join the transaction and leave it again.
 *
 * <p>The procedures answer with a return code in an output parameter and never
 * raise by themselves, which is why every call ends in a {@code select} and the
 * code is looked at.
 */
final class TdsXaResource extends AbstractXaResource {

    /** XA_OK - and what SQL Server writes as NULL when nothing went wrong. */
    private static final int XA_OK = 0;
    /** XA_RDONLY: the branch touched nothing, it is already finished. */
    private static final int XA_RDONLY = 3;
    /** TMONEPHASE, for a commit without a prepare. */
    private static final int TM_ONE_PHASE = 0x40000000;
    /** TMSUCCESS, the ordinary end of a branch. */
    private static final int TM_SUCCESS = 0x04000000;
    /** TMSTARTRSCAN, "begin the scan" for recover. */
    private static final int TM_START_SCAN = 0x01000000;

    private final TdsSession session;
    private final TdsConnection control;

    /**
     * @param control a second connection for the XA commands; it belongs to
     *                this resource and is closed with the XA connection
     */
    TdsXaResource(TdsConnection connection, TdsConnection control) throws SQLException {
        super(connection);
        this.session = connection.session();
        this.control = control;
    }

    @Override
    protected void begin(Xid xid) throws SQLException {
        String[] answer = call("declare @rc int, @msg nvarchar(1024), @dllver nvarchar(64), "
                + "@cookie varbinary(4000), @uow varbinary(4000); "
                + "exec master..sp_xa_start @rc output, @msg output, "
                + raw(xid.getGlobalTransactionId()) + ", " + raw(xid.getBranchQualifier())
                + ", 0, @cookie output, 0, " + xid.getFormatId() + ", @dllver output, "
                + "16, 0, 0x, 64, 64, 0, @uow output; "
                + "select isnull(@rc, 0), isnull(@msg, ''), "
                + "convert(varchar(max), @cookie, 2);", 3);
        check("xa_start", answer);
        String cookie = answer[2];
        if (cookie == null || cookie.isEmpty()) {
            throw new SQLException("the server started the branch but handed out no "
                    + "transaction cookie - without it this session cannot join it");
        }
        // The second half: without this the statements run outside the branch.
        enlist(unhex(cookie));
    }

    @Override
    protected void finish(Xid xid) throws SQLException {
        String[] answer = call("declare @rc int, @msg nvarchar(1024), @uow varbinary(4000); "
                + "exec master..sp_xa_end @rc output, @msg output, "
                + raw(xid.getGlobalTransactionId()) + ", " + raw(xid.getBranchQualifier())
                + ", " + TM_SUCCESS + ", " + xid.getFormatId() + ", @uow output; "
                + "select isnull(@rc, 0), isnull(@msg, '');", 2);
        check("xa_end", answer);
        leave();
    }

    @Override
    protected void prepareBranch(Xid xid) throws SQLException {
        check("xa_prepare", call("declare @rc int, @msg nvarchar(1024); "
                + "exec master..sp_xa_prepare @rc output, @msg output, "
                + raw(xid.getGlobalTransactionId()) + ", " + raw(xid.getBranchQualifier())
                + ", " + xid.getFormatId() + "; "
                + "select isnull(@rc, 0), isnull(@msg, '');", 2));
    }

    @Override
    protected void commitOnePhase(Xid xid) throws SQLException {
        commit(xid, TM_ONE_PHASE);
    }

    @Override
    protected void commitPrepared(Xid xid) throws SQLException {
        commit(xid, 0);
    }

    private void commit(Xid xid, int flags) throws SQLException {
        check("xa_commit", call("declare @rc int, @msg nvarchar(1024); "
                + "exec master..sp_xa_commit @rc output, @msg output, "
                + raw(xid.getGlobalTransactionId()) + ", " + raw(xid.getBranchQualifier())
                + ", " + flags + ", " + xid.getFormatId() + "; "
                + "select isnull(@rc, 0), isnull(@msg, '');", 2));
        session.transactionDescriptor(0);
    }

    @Override
    protected void rollbackBranch(Xid xid, boolean open) throws SQLException {
        check("xa_rollback", call("declare @rc int, @msg nvarchar(1024); "
                + "exec master..sp_xa_rollback @rc output, @msg output, "
                + raw(xid.getGlobalTransactionId()) + ", " + raw(xid.getBranchQualifier())
                + ", " + xid.getFormatId() + "; "
                + "select isnull(@rc, 0), isnull(@msg, '');", 2));
        session.transactionDescriptor(0);
    }

    @Override
    protected Xid[] scan() throws SQLException {
        String[] answer = call("declare @rc int, @msg nvarchar(1024), @xids varbinary(8000); "
                + "exec master..sp_xa_recover @rc output, @msg output, "
                + TM_START_SCAN + ", @xids output; "
                + "select isnull(@rc, 0), isnull(@msg, ''), "
                + "convert(varchar(max), @xids, 2);", 3);
        check("xa_recover", answer);
        return parse(unhex(answer[2]));
    }

    /**
     * Joins the session to the transaction the procedure opened.
     *
     * <p>The specification says the server answers with the descriptor as a
     * one-column result set. It does not - it sends an {@code ENVCHANGE},
     * exactly as when an ordinary transaction begins, and the session picks
     * the descriptor up on the way past. So there is nothing to read here;
     * what is checked is that a descriptor arrived at all, because without one
     * every following statement would run outside the branch and commit by
     * itself.
     */
    private void enlist(byte[] cookie) throws SQLException {
        session.transactionManager(Tds.TM_PROPAGATE_XACT, cookie, null);
        if (session.transactionDescriptor() == 0) {
            throw new SQLException("the server took the transaction but named no descriptor - "
                    + "the session would run outside the branch");
        }
    }

    /**
     * Takes the working session out of the transaction again.
     *
     * <p>Forgetting the descriptor is not enough: the server still has the
     * session inside the transaction and answers the next ordinary request
     * with error 3989. What ends it is the same request that began it, with an
     * empty cookie - "join nothing".
     */
    private void leave() throws SQLException {
        session.transactionManager(Tds.TM_PROPAGATE_XACT, new byte[0], null); // seclume-allow: an empty request payload
        session.transactionDescriptor(0);
    }

    /** One batch on the control connection, one row of values as text. */
    private String[] call(String batch, int count) throws SQLException {
        String[] values = new String[count];
        control.session().sqlBatch(batch, row -> {
            for (int i = 0; i < count && i < row.columnCount(); i++) {
                values[i] = row.isNull(i) ? "" : row.text(i);
            }
        });
        return values;
    }

    /** The return code, and the server's own words when it is not XA_OK. */
    private static void check(String what, String[] answer) throws SQLException {
        int code = answer[0] == null || answer[0].isEmpty() ? XA_OK
                : Integer.parseInt(answer[0].trim());
        if (code == XA_OK || code == XA_RDONLY) {
            return;
        }
        String message = answer[1] == null || answer[1].isBlank()
                ? "" : " - " + answer[1].trim();
        throw new SQLException(what + " answered " + code + message, "25000", code);
    }

    /**
     * The list of prepared branches: for each one the format id as four bytes,
     * then the two lengths as one byte each, then the bytes themselves. Found
     * by asking a server that had exactly one branch open, so that the layout
     * could not be misread.
     */
    private static Xid[] parse(byte[] blob) {
        List<Xid> found = new ArrayList<>();
        int at = 0;
        while (blob != null && at + 6 <= blob.length) {
            int formatId = (blob[at] & 0xff) | ((blob[at + 1] & 0xff) << 8)
                    | ((blob[at + 2] & 0xff) << 16) | ((blob[at + 3] & 0xff) << 24);
            int globalLength = blob[at + 4] & 0xff;
            int branchLength = blob[at + 5] & 0xff;
            int next = at + 6 + globalLength + branchLength;
            if (next > blob.length) {
                break;                             // a half entry is no entry
            }
            byte[] global = new byte[globalLength]; // seclume-allow: a transaction id, not a secret
            byte[] branch = new byte[branchLength]; // seclume-allow: a transaction id, not a secret
            System.arraycopy(blob, at + 6, global, 0, globalLength);
            System.arraycopy(blob, at + 6 + globalLength, branch, 0, branchLength);
            found.add(new XidText.Recovered(formatId, global, branch));
            at = next;
        }
        return found.toArray(new Xid[0]);
    }

    /** A binary literal; {@code 0x} alone is the empty one and is accepted. */
    private static String raw(byte[] bytes) {
        StringBuilder text = new StringBuilder(80); // seclume-allow: a transaction id, not a secret
        text.append("0x");
        if (bytes != null) {
            for (byte value : bytes) {
                text.append(Character.forDigit((value >> 4) & 0xf, 16));
                text.append(Character.forDigit(value & 0xf, 16));
            }
        }
        return text.toString();
    }

    private static byte[] unhex(String text) {
        if (text == null || text.length() % 2 != 0) {
            return new byte[0]; // seclume-allow: an empty list of transaction ids
        }
        byte[] bytes = new byte[text.length() / 2]; // seclume-allow: a transaction id, not a secret
        for (int i = 0; i < bytes.length; i++) {
            int high = Character.digit(text.charAt(i * 2), 16);
            int low = Character.digit(text.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                return new byte[0]; // seclume-allow: nothing readable, so nothing recovered
            }
            bytes[i] = (byte) ((high << 4) | low);
        }
        return bytes;
    }
}
