package space.seclume.postgresql.jdbc;

import java.util.Locale;

import space.seclume.internal.jdbc.CallSyntax;

/**
 * An {@code INSERT ... VALUES (?, ...)} taken apart, so that a batch of it can
 * be sent as {@code VALUES (...), (...), ...} - what
 * {@code rewriteBatchedInserts=true} does.
 *
 * <p>Only statements whose shape is beyond doubt are taken apart: an
 * {@code INSERT}, one {@code VALUES} tuple holding every placeholder, and after
 * it nothing, or an {@code ON CONFLICT} without placeholders. Anything else -
 * {@code INSERT ... SELECT}, a {@code WITH} in front, {@code RETURNING} (whose
 * keys would have to be matched to rows), a second tuple, a {@code $} (a
 * dollar-quoted string or an explicit {@code $1}) or a backslash (an
 * {@code E''} string), both of which the generic scanner reads differently
 * from PostgreSQL - returns null and the batch runs row by row as before.
 * Declining is always safe; guessing is not.
 */
final class InsertBatch {

    private final String head;
    private final String tuple;
    private final String tail;
    private final int parameters;

    private InsertBatch(String head, String tuple, String tail, int parameters) {
        this.head = head;
        this.tuple = tuple;
        this.tail = tail;
        this.parameters = parameters;
    }

    /** The placeholders in one row's tuple. */
    int parameters() {
        return parameters;
    }

    /** The statement for {@code rows} rows. */
    String sql(int rows) {
        StringBuilder text = new StringBuilder(head.length() + rows * (tuple.length() + 2)
                + tail.length());
        text.append(head);
        for (int row = 0; row < rows; row++) {
            if (row > 0) {
                text.append(", ");
            }
            text.append(tuple);
        }
        return text.append(tail).toString();
    }

    /** The statement taken apart, or null when it is not a plain multi-row-able insert. */
    static InsertBatch parse(String sql) {
        if (sql == null || sql.indexOf('\\') >= 0 || sql.indexOf('$') >= 0) {
            return null;
        }
        boolean[] code = CallSyntax.codeMask(sql);
        int at = skipSpace(sql, code, 0);
        if (!word(sql, code, at, "insert")) {
            return null;
        }
        int values = -1;
        int keywordLength = 0;
        for (int i = at; i < sql.length(); i++) {
            if (word(sql, code, i, "select")) {
                return null;
            }
            if (word(sql, code, i, "values")) {
                values = i;
                keywordLength = 6;
                break;
            }
        }
        if (values < 0) {
            return null;
        }
        int open = skipSpace(sql, code, values + keywordLength);
        if (open >= sql.length() || !code[open] || sql.charAt(open) != '(') {
            return null;
        }
        int depth = 0;
        int close = -1;
        for (int i = open; i < sql.length(); i++) {
            if (!code[i]) {
                continue;
            }
            char c = sql.charAt(i);
            if (c == '(') {
                depth++;
            } else if (c == ')' && --depth == 0) {
                close = i;
                break;
            }
        }
        if (close < 0) {
            return null;
        }
        String tail = sql.substring(close + 1);
        String rest = tail.strip().toLowerCase(Locale.ROOT);
        if (rest.endsWith(";")) {
            return null;                              // one statement, not a script
        }
        String spaced = " " + rest.replaceAll("\\s+", " ") + " ";
        if (!rest.isEmpty() && !spaced.startsWith(" on conflict ")) {
            return null;                              // a second tuple, or something unknown
        }
        if (spaced.contains(" returning ")) {
            return null;                              // keys per row would have to be matched
        }
        int[] placeholders = CallSyntax.placeholderOffsets(sql);
        if (placeholders.length == 0) {
            return null;
        }
        for (int offset : placeholders) {
            if (offset < open || offset > close) {
                return null;                          // a placeholder outside the tuple
            }
        }
        return new InsertBatch(sql.substring(0, open), sql.substring(open, close + 1), tail,
                placeholders.length);
    }

    private static int skipSpace(String sql, boolean[] code, int at) {
        while (at < sql.length() && (!code[at] || Character.isWhitespace(sql.charAt(at)))) {
            at++;
        }
        return at;
    }

    /** Whether the keyword stands at {@code at} as a whole word, in code. */
    private static boolean word(String sql, boolean[] code, int at, String keyword) {
        int end = at + keyword.length();
        if (end > sql.length() || !code[at] || !sql.regionMatches(true, at, keyword, 0,
                keyword.length())) {
            return false;
        }
        boolean before = at == 0 || !Character.isLetterOrDigit(sql.charAt(at - 1))
                && sql.charAt(at - 1) != '_';
        boolean after = end == sql.length() || !Character.isLetterOrDigit(sql.charAt(end))
                && sql.charAt(end) != '_';
        return before && after;
    }
}
