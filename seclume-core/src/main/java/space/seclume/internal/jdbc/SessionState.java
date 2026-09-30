package space.seclume.internal.jdbc;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * What statements have set in a session beyond its transaction - noted as
 * they pass, for {@link space.seclume.SessionReset}.
 *
 * <p>This is a diagnostic heuristic, not an isolation boundary. Side effects
 * inside functions and procedures cannot be inferred from SQL text. Pools
 * must reset used sessions even when {@link #changed()} returns false.
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
        // One statement unless there is a semicolon somewhere: then the text is
        // judged whole, without working out which characters are code.
        if (sql.indexOf(';') < 0) {
            judge(sql);
            if (mayContain(sql) && ANYWHERE.matcher(sql).find()) {
                changed = true;
            }
            return;
        }
        boolean[] code = CallSyntax.codeMask(sql);
        int from = 0;
        for (int i = 0; i <= sql.length(); i++) {
            if (i < sql.length() && !(code[i] && sql.charAt(i) == ';')) {
                continue;
            }
            judge(sql.substring(from, i));
            from = i + 1;
        }
        if (mayContain(sql) && ANYWHERE.matcher(sql).find()) {
            changed = true;
        }
    }

    /** One statement's leading words. */
    private void judge(String statement) {
        String start = leading(statement);
        if (mayLead(start) && LEADING.matcher(start).find()) {
            changed = true;
            if (IRREVERSIBLE.matcher(start).find()) {
                irreversible = true;
            }
        }
    }

    /**
     * The words {@link #LEADING} can begin with. A statement that begins with
     * none of them cannot match it - most statements, {@code select} first -
     * and is spared the expression, which was a tenth of the allocation of a
     * {@code select 1} (JFR, 30.09.2026). Only a filter: whatever passes it is
     * decided by the expression as before.
     */
    private static final String[] LEADING_WORDS = {"set", "use", "prepare", "listen", "alter",
        "exec", "create", "declare"};

    private static boolean mayLead(String start) {
        if (start.isEmpty()) {
            return false;
        }
        switch (Character.toLowerCase(start.charAt(0))) {
            case 's', 'u', 'p', 'l', 'a', 'e', 'c', 'd' -> { }
            default -> {
                return false;
            }
        }
        for (String word : LEADING_WORDS) {
            if (start.regionMatches(true, 0, word, 0, word.length())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Every form {@link #ANYWHERE} looks for has an underscore, a {@code #} or
     * an {@code @} in it; a statement without any of the three cannot match.
     */
    private static boolean mayContain(String sql) {
        return sql.indexOf('_') >= 0 || sql.indexOf('#') >= 0 || sql.indexOf('@') >= 0;
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
