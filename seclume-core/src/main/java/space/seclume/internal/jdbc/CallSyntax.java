package space.seclume.internal.jdbc;

import java.sql.SQLException;

/**
 * The shape of a {@code CallableStatement}'s SQL, taken apart once for all
 * four drivers.
 *
 * <p>JDBC writes a procedure call in an escape syntax that no database
 * speaks: <code>{call p(?, ?)}</code>, or <code>{? = call f(?)}</code> when
 * the first parameter is the return value. Every driver has to turn that
 * into something its own server understands, and each turns it into
 * something different - PostgreSQL into {@code CALL}, MySQL into
 * {@code CALL} with session variables for the outputs, SQL Server into an
 * RPC by name, Oracle into an anonymous PL/SQL block. What they share is
 * the taking-apart, which is this.
 *
 * <p><b>The braces are optional</b> and so is the argument list: every
 * driver in the wild accepts {@code call p} and {@code call p()} as well as
 * the escaped form, and an application that worked elsewhere should not
 * fail here over a brace.
 *
 * <p>The question marks are counted rather than the arguments split, and
 * they are counted <b>outside literals and comments</b> - {@code call
 * p('a?b', ?)} has one parameter, not two. That is the same trap the
 * per-driver rewriters already deal with for ordinary statements, and
 * getting it wrong here would number every following parameter one too
 * high.
 */
public record CallSyntax(String name, String arguments, int parameters, boolean returnsValue) {

    /**
     * Takes a call apart.
     *
     * @throws SQLException if this is not a procedure call at all - said
     *                      plainly, because the alternative is a server
     *                      error about syntax the application never wrote
     */
    public static CallSyntax parse(String sql) throws SQLException {
        if (sql == null || sql.isBlank()) {
            throw new SQLException("a callable statement needs SQL, and this one is empty");
        }
        String text = sql.trim();
        if (text.startsWith("{")) {
            if (!text.endsWith("}")) {
                throw new SQLException("the call starts with '{' and does not end with '}': " + sql);
            }
            text = text.substring(1, text.length() - 1).trim();
        }

        boolean returnsValue = false;
        if (text.startsWith("?")) {
            int equals = text.indexOf('=');
            if (equals < 0 || !text.substring(1, equals).isBlank()) {
                throw new SQLException("a call that starts with '?' has to continue '= call': "
                        + sql);
            }
            returnsValue = true;
            text = text.substring(equals + 1).trim();
        }

        if (text.length() < 4 || !text.substring(0, 4).equalsIgnoreCase("call")
                || (text.length() > 4 && !Character.isWhitespace(text.charAt(4))
                    && text.charAt(4) != '(')) {
            throw new SQLException("this is not a procedure call - a callable statement reads "
                    + "'{call p(?)}' or '{? = call f(?)}', and this is: " + sql);
        }
        text = text.substring(4).trim();

        String name = text;
        String arguments = "";
        int open = text.indexOf('(');
        if (open >= 0) {
            // The bracket that matches, not the last one in the string: a
            // comment after the call may hold a bracket of its own, and
            // taking the last would swallow it into the argument list.
            int close = matchingParen(text, open);
            if (close < 0) {
                throw new SQLException("the argument list of the call is not closed: " + sql);
            }
            if (!isBlankOrComment(text.substring(close + 1))) {
                throw new SQLException("there is more after the call than its arguments: " + sql);
            }
            name = text.substring(0, open).trim();
            arguments = text.substring(open + 1, close).trim();
        }
        if (name.isEmpty()) {
            throw new SQLException("the call names no procedure: " + sql);
        }
        return new CallSyntax(name, arguments, countPlaceholders(arguments), returnsValue);
    }

    /** How many parameters the statement has altogether, the return value included. */
    public int totalParameters() {
        return parameters + (returnsValue ? 1 : 0);
    }

    /**
     * Question marks that are really parameters - not the ones inside a
     * string, an identifier or a comment.
     */
    private static int countPlaceholders(String arguments) {
        int count = 0;
        int at = 0;
        while (at < arguments.length()) {
            int skipped = skipNonCode(arguments, at);
            if (skipped != at) {
                at = skipped;
                continue;
            }
            if (arguments.charAt(at) == '?') {
                count++;
            }
            at++;
        }
        return count;
    }

    /**
     * The bracket that closes the one at {@code open}, or -1.
     *
     * <p>Counts depth, so a nested call in the argument list keeps its own
     * brackets, and steps over literals and comments so that a bracket
     * inside one of those does not count.
     */
    private static int matchingParen(String text, int open) {
        int depth = 0;
        int at = open;
        while (at < text.length()) {
            int skipped = skipNonCode(text, at);
            if (skipped != at) {
                at = skipped;
                continue;
            }
            char c = text.charAt(at);
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
                if (depth == 0) {
                    return at;
                }
            }
            at++;
        }
        return -1;
    }

    /** Whether what follows the call is nothing that changes it. */
    private static boolean isBlankOrComment(String rest) {
        int at = 0;
        while (at < rest.length()) {
            int skipped = skipNonCode(rest, at);
            if (skipped != at) {
                at = skipped;
                continue;
            }
            if (!Character.isWhitespace(rest.charAt(at))) {
                return false;
            }
            at++;
        }
        return true;
    }

    /**
     * Past a literal or a comment starting here; the same position back if
     * this is ordinary code.
     *
     * <p>In one place, because three callers have to agree about what is not
     * code - and a disagreement between them is exactly how a bracket inside
     * a string ends up counted as one.
     */
    private static int skipNonCode(String text, int at) {
        char c = text.charAt(at);
        if (c == '\'' || c == '"' || c == '`') {
            return skipQuoted(text, at, c);
        }
        if (c == '-' && at + 1 < text.length() && text.charAt(at + 1) == '-') {
            int end = text.indexOf('\n', at);
            return end < 0 ? text.length() : end + 1;
        }
        if (c == '/' && at + 1 < text.length() && text.charAt(at + 1) == '*') {
            int end = text.indexOf("*/", at + 2);
            return end < 0 ? text.length() : end + 2;
        }
        return at;
    }

    /** Past a quoted run, treating a doubled quote as one that stays inside. */
    private static int skipQuoted(String text, int start, char quote) {
        int at = start + 1;
        while (at < text.length()) {
            if (text.charAt(at) == quote) {
                if (at + 1 < text.length() && text.charAt(at + 1) == quote) {
                    at += 2;                  // an escaped quote, still inside
                    continue;
                }
                return at + 1;
            }
            at++;
        }
        return at;                            // unterminated; the server will say so
    }
}
