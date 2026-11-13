package space.seclume.mysql.jdbc;

import java.sql.SQLException;

/**
 * {@code Statement.enquoteLiteral} and {@code enquoteIdentifier} for MySQL.
 *
 * <p>JDBC's own versions of both are written for standard SQL and are wrong
 * here, one of them dangerously. A literal is made there by doubling each
 * single quote and nothing else. MySQL also reads a backslash as an escape
 * (unless the session's {@code sql_mode} has {@code NO_BACKSLASH_ESCAPES}), so
 * {@code \' or 1=1 -- } became {@code '\'' or 1=1 -- '}: the backslash takes
 * the first quote, the second ends the string, and the rest is SQL - an
 * injection through the method an application calls to prevent one. And an
 * identifier is put in double quotes there, which MySQL reads as a string
 * unless {@code ANSI_QUOTES} is set: {@code select "name" from t} answers the
 * word, not the column.
 */
final class MyQuoting {

    private MyQuoting() {
    }

    /**
     * {@code value} as a string literal.
     *
     * @param noBackslashEscapes whether the session reads a backslash as itself -
     *                           the server says so with every answer
     */
    static String literal(String value, boolean noBackslashEscapes) {
        StringBuilder literal = new StringBuilder(value.length() + 8).append('\'');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\'') {
                literal.append("''");
            } else if (c == '\\' && !noBackslashEscapes) {
                literal.append("\\\\");
            } else {
                literal.append(c);
            }
        }
        return literal.append('\'').toString();
    }

    /**
     * {@code identifier} in backticks, a backtick in it doubled - or as it is
     * when it needs none and {@code alwaysQuote} is false, or when it is in
     * backticks already.
     */
    static String identifier(String identifier, boolean alwaysQuote) throws SQLException {
        if (identifier.isEmpty() || identifier.indexOf('\0') >= 0) {
            throw new SQLException("not an identifier: empty, or with a NUL character", "42000");
        }
        if (identifier.length() >= 2 && identifier.charAt(0) == '`'
                && identifier.charAt(identifier.length() - 1) == '`') {
            String inner = identifier.substring(1, identifier.length() - 1);
            if (inner.isEmpty() || inner.replace("``", "").indexOf('`') >= 0) {
                throw new SQLException("not a quoted identifier: a backtick in it is not doubled",
                        "42000");
            }
            return identifier;
        }
        if (!alwaysQuote && simple(identifier)) {
            return identifier;
        }
        return "`" + identifier.replace("`", "``") + "`";
    }

    /** Letters, digits and underscores after a letter: what needs no quotes in any mode. */
    static boolean simple(String identifier) {
        if (identifier.isEmpty() || identifier.length() > 64) {
            return false;
        }
        for (int i = 0; i < identifier.length(); i++) {
            char c = identifier.charAt(i);
            boolean letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            if (!letter && (i == 0 || !((c >= '0' && c <= '9') || c == '_'))) {
                return false;
            }
        }
        return true;
    }
}
