package space.seclume.mysql.jdbc;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import javax.transaction.xa.Xid;

import space.seclume.internal.jdbc.AbstractXaResource;
import space.seclume.internal.jdbc.XidText;

/**
 * Two-phase commit for MySQL and MariaDB.
 *
 * <p>Here it is a statement family of its own: {@code XA START}, {@code XA
 * END}, {@code XA PREPARE}, {@code XA COMMIT} and {@code XA ROLLBACK}, each
 * taking the transaction id as three parts - two byte strings and a number.
 * That fits {@link Xid} exactly, so unlike PostgreSQL nothing has to be
 * flattened into one name; the parts go over as hexadecimal literals and come
 * back byte for byte.
 *
 * <p>The order is stricter than elsewhere: the server refuses a prepare or a
 * commit while the branch is still {@code ACTIVE}. A transaction manager sends
 * the {@code end} itself, but a caller who does not is not left with a useless
 * error - the {@code XA END} is then sent along.
 *
 * <p>Recovery reads {@code XA RECOVER CONVERT XID}, which returns the id in
 * hexadecimal. Plain {@code XA RECOVER} would hand back raw bytes in a text
 * column, and any id that is not valid UTF-8 would come back damaged - which
 * is the one thing recovery must not do. MariaDB does not know
 * {@code CONVERT XID}; its {@code XA RECOVER FORMAT='SQL'} writes the id as
 * the XA statements take it, {@code X'..',X'..',n}, which is as safe.
 */
final class MyXaResource extends AbstractXaResource {

    private final MyConnection session;
    private boolean ended;

    MyXaResource(MyConnection session) {
        super(session);
        this.session = session;
    }

    @Override
    protected void begin(Xid xid) throws SQLException {
        run("xa start " + parts(xid));
        ended = false;
    }

    @Override
    protected void finish(Xid xid) throws SQLException {
        endOnce(xid);
    }

    @Override
    protected void prepareBranch(Xid xid) throws SQLException {
        endOnce(xid);
        run("xa prepare " + parts(xid));
    }

    @Override
    protected void commitOnePhase(Xid xid) throws SQLException {
        endOnce(xid);
        run("xa commit " + parts(xid) + " one phase");
    }

    @Override
    protected void commitPrepared(Xid xid) throws SQLException {
        run("xa commit " + parts(xid));
    }

    @Override
    protected void rollbackBranch(Xid xid, boolean open) throws SQLException {
        if (open) {
            endOnce(xid);
        }
        run("xa rollback " + parts(xid));
    }

    @Override
    protected Xid[] scan() throws SQLException {
        List<Xid> found = new ArrayList<>();
        boolean mariaDb = session.session().isMariaDb();
        try (Statement statement = session.createStatement();
             ResultSet rows = statement.executeQuery(mariaDb ? "xa recover format='SQL'"
                     : "xa recover convert xid")) {
            while (rows.next()) {
                int formatId = rows.getInt("formatID");
                int gtridLength = rows.getInt("gtrid_length");
                int bqualLength = rows.getInt("bqual_length");
                byte[] data = mariaDb ? fromSqlFormat(rows.getString("data"), formatId) // seclume-allow: a transaction id, not a secret
                        : unhex(rows.getString("data"));
                if (data == null || data.length < gtridLength + bqualLength) {
                    continue;                    // not ours, or not what we asked for
                }
                byte[] global = new byte[gtridLength]; // seclume-allow: a transaction id, not a secret
                byte[] branch = new byte[bqualLength]; // seclume-allow: a transaction id, not a secret
                System.arraycopy(data, 0, global, 0, gtridLength);
                System.arraycopy(data, gtridLength, branch, 0, bqualLength);
                found.add(new XidText.Recovered(formatId, global, branch));
            }
        } catch (SQLException e) {
            if (e.getErrorCode() == MISSING_RECOVER_PRIVILEGE) {
                // The server says "fatal error in the branch", which is about
                // as far from the truth as it gets: nothing is broken, the
                // account is simply not allowed to look.
                throw new SQLException("this account may not list prepared transactions - "
                        + "MySQL wants the XA_RECOVER_ADMIN privilege for that: "
                        + "grant xa_recover_admin on *.* to <user>", e.getSQLState(),
                        e.getErrorCode(), e);
            }
            throw e;
        }
        return found.toArray(new Xid[0]);
    }

    /** ER_XAER_RMERR - what MySQL answers when XA_RECOVER_ADMIN is missing. */
    private static final int MISSING_RECOVER_PRIVILEGE = 1399;

    /** The three parts of the id, ready for an XA statement. */
    private static String parts(Xid xid) {
        StringBuilder text = new StringBuilder(80); // seclume-allow: a transaction id, not a secret
        appendLiteral(text, xid.getGlobalTransactionId());
        text.append(',');
        appendLiteral(text, xid.getBranchQualifier());
        text.append(',').append(xid.getFormatId());
        return text.toString();
    }

    private static void appendLiteral(StringBuilder text, byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            text.append("''");                   // X'' is not accepted everywhere
            return;
        }
        text.append("X'");
        for (byte value : bytes) {
            text.append(Character.forDigit((value >> 4) & 0xf, 16));
            text.append(Character.forDigit(value & 0xf, 16));
        }
        text.append('\'');
    }

    /**
     * MariaDB's {@code X'4142',X'43',1} - global id, branch, format - as the
     * id's bytes, global then branch; {@code null} for anything else.
     */
    static byte[] fromSqlFormat(String text, int formatId) {
        if (text == null) {
            return null;
        }
        String[] parts = text.split(",", -1);
        if (parts.length != 3 || !parts[2].strip().equals(Integer.toString(formatId))) {
            return null;
        }
        byte[] global = literal(parts[0].strip()); // seclume-allow: a transaction id, not a secret
        byte[] branch = literal(parts[1].strip()); // seclume-allow: a transaction id, not a secret
        if (global == null || branch == null) {
            return null;
        }
        byte[] data = new byte[global.length + branch.length]; // seclume-allow: a transaction id, not a secret
        System.arraycopy(global, 0, data, 0, global.length);
        System.arraycopy(branch, 0, data, global.length, branch.length);
        return data;
    }

    /** {@code X'4142'} or {@code ''}. */
    private static byte[] literal(String text) {
        if (text.equals("''") || text.equalsIgnoreCase("X''")) {
            return new byte[0]; // seclume-allow: an empty transaction id part
        }
        if (text.length() < 3 || (text.charAt(0) != 'X' && text.charAt(0) != 'x')
                || text.charAt(1) != '\'' || text.charAt(text.length() - 1) != '\'') {
            return null;
        }
        return unhex(text.substring(2, text.length() - 1));
    }

    /** {@code 0x4142..} as the server writes it after CONVERT XID. */
    private static byte[] unhex(String text) {
        if (text == null) {
            return null;
        }
        String digits = text.startsWith("0x") || text.startsWith("0X")
                ? text.substring(2) : text;
        if (digits.length() % 2 != 0) {
            return null;
        }
        byte[] bytes = new byte[digits.length() / 2]; // seclume-allow: a transaction id, not a secret
        for (int i = 0; i < bytes.length; i++) {
            int high = Character.digit(digits.charAt(i * 2), 16);
            int low = Character.digit(digits.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                return null;
            }
            bytes[i] = (byte) ((high << 4) | low);
        }
        return bytes;
    }

    private void endOnce(Xid xid) throws SQLException {
        if (!ended) {
            run("xa end " + parts(xid));
            ended = true;
        }
    }
}
