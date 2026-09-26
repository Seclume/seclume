package space.seclume.sqlserver.jdbc;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;

import space.seclume.sqlserver.tds.TdsParameters;

/**
 * Which text parameters of a statement the server compares with a
 * {@code varchar} column - asked once per statement text and process.
 *
 * <p>The question goes to {@code sp_describe_undeclared_parameters}, with the
 * parameters whose type is already clear declared, so the server only deduces
 * the text ones. It answers {@code varchar} for {@code where code = @P0} on a
 * {@code varchar} column, and {@code nvarchar} where the column is
 * {@code nvarchar} or there is no column to go by. See
 * {@link TdsParameters#preferVarchar} for what is done with the answer, and why
 * only ASCII text is ever sent as {@code varchar}.
 *
 * <p><b>Never inside a transaction.</b> A statement the server cannot describe
 * is an error, and with {@code XACT_ABORT ON} an error rolls the transaction
 * back - the caller's work, for a question the caller never asked. So inside
 * one the answer is "not known yet", the text goes as {@code nvarchar} as it
 * always did, and the question waits for a moment outside a transaction.
 *
 * <p>An answer is kept per server, database and statement text, for every
 * connection of the process; a statement the server could not describe is
 * remembered as such and not asked about again.
 */
final class VarcharParameters {

    /** Statement texts remembered; beyond this the oldest answer is asked again. */
    private static final int REMEMBERED = 2048;

    private static final boolean[] NONE = new boolean[0];

    private static final Map<String, boolean[]> KNOWN =
            new LinkedHashMap<>(256, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, boolean[]> eldest) {
                    return size() > REMEMBERED;
                }
            };

    private VarcharParameters() {
    }

    /**
     * The flags for {@code sql} - the statement text with its {@code @P}
     * names - or null when no parameter goes as varchar.
     */
    static boolean[] of(TdsConnection connection, String sql, TdsParameters parameters)
            throws SQLException {
        if (!connection.varcharParameters() || !parameters.hasText()) {
            return null;
        }
        String key = connection.serverKey() + "\n" + sql;
        boolean[] known;
        synchronized (KNOWN) {
            known = KNOWN.get(key);
        }
        if (known == null) {
            if (!connection.getAutoCommit() || connection.session().transactionDescriptor() != 0) {
                return null;
            }
            known = ask(connection, sql, parameters);
            synchronized (KNOWN) {
                KNOWN.put(key, known);
            }
        }
        return known.length == 0 ? null : known;
    }

    private static boolean[] ask(TdsConnection connection, String sql, TdsParameters parameters)
            throws SQLException {
        String declared = parameters.declarationOfNonText();
        // The application's own statement as an N'...' literal, quotes doubled -
        // T-SQL has no other escape. nosemgrep: java.lang.security.audit.formatted-sql-string.formatted-sql-string
        String question = "exec sp_describe_undeclared_parameters @tsql = N'"
                + sql.replace("'", "''") + "'"
                + (declared.isEmpty() ? "" : ", @params = N'" + declared.replace("'", "''") + "'");
        boolean[] varchar = new boolean[parameters.count()];
        boolean any = false;
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(question)) { // nosemgrep: java.lang.security.audit.formatted-sql-string.formatted-sql-string
            while (rows.next()) {
                String name = rows.getString("name");
                int type = rows.getInt("suggested_system_type_id");
                // 167 varchar, 175 char - the two a varchar parameter serves.
                if ((type == 167 || type == 175) && name != null && name.startsWith("@P")) {
                    int index = Integer.parseInt(name.substring(2));
                    if (index >= 0 && index < varchar.length) {
                        varchar[index] = true;
                        any = true;
                    }
                }
            }
        } catch (SQLException | NumberFormatException undescribable) {
            // Not every statement can be described - a parameter used twice
            // in different roles, a temporary table made by the batch itself.
            // Such a statement keeps nvarchar, as before.
            return NONE;
        }
        return any ? varchar : NONE;
    }

    /** Forgets every answer - for a test that changes a column's type. */
    static void forget() {
        synchronized (KNOWN) {
            KNOWN.clear();
        }
    }
}
