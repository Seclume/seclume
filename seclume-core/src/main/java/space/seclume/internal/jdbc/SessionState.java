package space.seclume.internal.jdbc;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * What statements have set in a session beyond its transaction - noted as
 * they pass, for {@link space.seclume.SessionReset}.
 *
 * <p>A statement is recognised by its first word and by a handful of calls
 * anywhere in it. The list errs on the side of noting: a false alarm costs one
 * reset when the connection goes back to the pool, a statement missed costs
 * the next borrower the session state of the previous one.
 */
public final class SessionState {

    /** First words - after comments and parentheses - that set session state. */
    private static final Pattern LEADING = Pattern.compile(
            "^(set|use|prepare|listen|alter\\s+session|exec(ute)?\\s+as\\s|setuser"
                    + "|create\\s+(local\\s+|global\\s+)?temp(orary)?\\s"
                    + "|create\\s+table\\s+#"
                    + "|declare\\s+\\S+\\s+(binary\\s+)?(insensitive\\s+)?(no\\s+)?(scroll\\s+)?"
                    + "cursor\\s+with\\s+hold)",
            Pattern.CASE_INSENSITIVE);

    /** Calls and forms anywhere in a statement that set session state. */
    private static final Pattern ANYWHERE = Pattern.compile(
            "set_config\\s*\\(|dbms_session\\s*\\.|dbms_application_info\\s*\\."
                    + "|sp_setapprole|sp_set_session_context|context_info"
                    + "|pg_advisory_lock\\s*\\(|pg_try_advisory_lock\\s*\\(|get_lock\\s*\\("
                    + "|\\binto\\s+#|@\\w+\\s*:=",
            Pattern.CASE_INSENSITIVE);

    /** What Oracle cannot put back without a new session. */
    private static final Pattern IRREVERSIBLE = Pattern.compile("^alter\\s+session",
            Pattern.CASE_INSENSITIVE);

    private volatile boolean changed;
    private volatile boolean irreversible;

    /** One per connection, noting from its first statement on. */
    public SessionState() {
    }

    /** Notes one statement's text. */
    public void note(String sql) {
        if (sql == null || (changed && irreversible)) {
            return;
        }
        // Every statement of a batch, not only the first: "select 1; set role
        // admin" sets a role as surely as "set role admin" does. A missed one
        // hands the next borrower the rights or the tenant of the previous
        // (found in review, 25.09.2026).
        boolean[] code = CallSyntax.codeMask(sql);
        int from = 0;
        for (int i = 0; i <= sql.length(); i++) {
            if (i < sql.length() && !(code[i] && sql.charAt(i) == ';')) {
                continue;
            }
            String start = leading(sql.substring(from, i));
            if (LEADING.matcher(start).find()) {
                changed = true;
                if (IRREVERSIBLE.matcher(start).find()) {
                    irreversible = true;
                }
            }
            from = i + 1;
        }
        if (ANYWHERE.matcher(sql).find()) {
            changed = true;
        }
    }

    /** Whether a statement since the last {@link #clear()} set something. */
    public boolean changed() {
        return changed;
    }

    /** Whether one of them was an {@code ALTER SESSION}. */
    public boolean irreversible() {
        return irreversible;
    }

    /** After a reset. */
    public void clear() {
        changed = false;
        irreversible = false;
    }

    /** Whether one statement's text would be noted - for the drivers' tests. */
    public static boolean sets(String sql) {
        SessionState probe = new SessionState();
        probe.note(sql);
        return probe.changed();
    }

    /** The text from its first word on: comments, blanks and opening parentheses skipped. */
    private static String leading(String sql) {
        int i = 0;
        int n = sql.length();
        while (i < n) {
            char c = sql.charAt(i);
            if (Character.isWhitespace(c) || c == '(' || c == ';') {
                i++;
            } else if (sql.startsWith("--", i)) {
                int end = sql.indexOf('\n', i);
                i = end < 0 ? n : end + 1;
            } else if (sql.startsWith("/*", i)) {
                int end = sql.indexOf("*/", i + 2);
                i = end < 0 ? n : end + 2;
            } else {
                break;
            }
        }
        return sql.substring(i, Math.min(n, i + 200)).toLowerCase(Locale.ROOT);
    }
}
