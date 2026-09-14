package space.seclume.oracle.jdbc;

import java.sql.SQLException;

/**
 * Turns JDBC's question marks into Oracle's numbered bind variables.
 *
 * <p>Oracle knows no question mark. It takes {@code :1}, {@code :2} and so on,
 * and the values arrive in that order - so the translation is a renumbering,
 * not a substitution: the value never enters the text.
 *
 * <p>Reading, not replacing, because a question mark does not mean the same
 * thing everywhere:
 *
 * <ul>
 *   <li>inside {@code 'text?'} it is text - and {@code ''} is the escaped
 *       quote,</li>
 *   <li>inside {@code "column?"} it is part of an identifier,</li>
 *   <li>inside {@code -- ?} and {@code /* ? *&#47;} it is a comment; Oracle's
 *       block comments do <b>not</b> nest, unlike T-SQL's,</li>
 *   <li>inside {@code q'[text?]'} it is text as well - the alternative quoting
 *       mechanism, where the delimiter is whatever follows the {@code q'}.</li>
 * </ul>
 *
 * <p>A {@code String.replace} would be one line, and would destroy every
 * question mark in every literal as soon as somebody writes one.
 */
final class OraSqlRewriter {

    /** The result: rewritten SQL and the number of placeholders. */
    record Rewritten(String sql, int parameters) {
    }

    private OraSqlRewriter() {
    }

    static Rewritten rewrite(String sql) throws SQLException {
        StringBuilder out = new StringBuilder(sql.length() + 16); // seclume-allow: SQL text, never a secret
        int parameters = 0;
        int i = 0;
        int length = sql.length();
        while (i < length) {
            char c = sql.charAt(i);
            switch (c) {
                case '\'' -> i = copyQuoted(sql, i, out);
                case '"' -> i = copyIdentifier(sql, i, out);
                case 'q', 'Q' -> {
                    if (i + 1 < length && sql.charAt(i + 1) == '\'') {
                        i = copyAlternativeQuoted(sql, i, out);
                    } else {
                        out.append(c);
                        i++;
                    }
                }
                case '-' -> {
                    if (i + 1 < length && sql.charAt(i + 1) == '-') {
                        i = copyLineComment(sql, i, out);
                    } else {
                        out.append(c);
                        i++;
                    }
                }
                case '/' -> {
                    if (i + 1 < length && sql.charAt(i + 1) == '*') {
                        i = copyBlockComment(sql, i, out);
                    } else {
                        out.append(c);
                        i++;
                    }
                }
                case '?' -> {
                    out.append(':').append(++parameters);
                    i++;
                }
                default -> {
                    out.append(c);
                    i++;
                }
            }
        }
        return new Rewritten(out.toString(), parameters);
    }

    /** A string literal; {@code ''} inside it is one quote and not the end. */
    private static int copyQuoted(String sql, int start, StringBuilder out)
            throws SQLException {
        out.append('\'');
        int i = start + 1;
        while (i < sql.length()) {
            char c = sql.charAt(i);
            out.append(c);
            if (c == '\'') {
                if (i + 1 < sql.length() && sql.charAt(i + 1) == '\'') {
                    out.append('\'');
                    i += 2;
                    continue;
                }
                return i + 1;
            }
            i++;
        }
        throw new SQLException("unterminated string literal in: " + sql);
    }

    /** A quoted identifier - no escape inside, a quote ends it. */
    private static int copyIdentifier(String sql, int start, StringBuilder out)
            throws SQLException {
        out.append('"');
        int i = start + 1;
        while (i < sql.length()) {
            char c = sql.charAt(i);
            out.append(c);
            i++;
            if (c == '"') {
                return i;
            }
        }
        throw new SQLException("unterminated quoted identifier in: " + sql);
    }

    /**
     * Oracle's alternative quoting: {@code q'<delimiter>text<delimiter>'}. The
     * delimiter is whatever character follows, and if it is a bracket the
     * closing one is its mirror image.
     */
    private static int copyAlternativeQuoted(String sql, int start, StringBuilder out)
            throws SQLException {
        if (start + 2 >= sql.length()) {
            throw new SQLException("unterminated quoted literal in: " + sql);
        }
        char open = sql.charAt(start + 2);
        char close = switch (open) {
            case '[' -> ']';
            case '{' -> '}';
            case '(' -> ')';
            case '<' -> '>';
            default -> open;
        };
        out.append(sql, start, start + 3);
        int i = start + 3;
        while (i + 1 < sql.length()) {
            if (sql.charAt(i) == close && sql.charAt(i + 1) == '\'') {
                out.append(close).append('\'');
                return i + 2;
            }
            out.append(sql.charAt(i));
            i++;
        }
        throw new SQLException("unterminated quoted literal in: " + sql);
    }

    private static int copyLineComment(String sql, int start, StringBuilder out) {
        int i = start;
        while (i < sql.length() && sql.charAt(i) != '\n') {
            out.append(sql.charAt(i));
            i++;
        }
        return i;
    }

    /** A block comment; in Oracle it ends at the first {@code *&#47;}. */
    private static int copyBlockComment(String sql, int start, StringBuilder out)
            throws SQLException {
        out.append("/*");
        int i = start + 2;
        while (i + 1 < sql.length()) {
            if (sql.charAt(i) == '*' && sql.charAt(i + 1) == '/') {
                out.append("*/");
                return i + 2;
            }
            out.append(sql.charAt(i));
            i++;
        }
        throw new SQLException("unterminated block comment in: " + sql);
    }
}
