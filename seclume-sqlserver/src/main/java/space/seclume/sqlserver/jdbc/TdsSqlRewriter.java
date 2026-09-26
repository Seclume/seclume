package space.seclume.sqlserver.jdbc;

import java.sql.SQLException;

/**
 * Turns JDBC's question marks into SQL Server's named parameters.
 *
 * <p>{@code sp_executesql} takes the statement text with names in it -
 * {@code where id = @P0} - and the values next to it. JDBC writes a question
 * mark, so it has to be translated, and the translation has to read rather
 * than replace: a question mark does not mean the same thing everywhere.
 *
 * <ul>
 *   <li>inside {@code 'text?'} it is text,</li>
 *   <li>inside {@code [column?]} it is part of an identifier - and there
 *       {@code ]]} is the escaped bracket,</li>
 *   <li>inside {@code "column?"} likewise, when {@code quoted_identifier} is
 *       on, which it is by default,</li>
 *   <li>inside {@code -- ?} and {@code /* ? *&#47;} it is a comment. T-SQL
 *       block comments nest, unlike almost every other dialect.</li>
 * </ul>
 *
 * <p>A {@code String.replace} would be one line - and would destroy every
 * question mark in every text literal as soon as somebody writes one.
 */
final class TdsSqlRewriter {

    /** The result: rewritten SQL and the number of placeholders. */
    record Rewritten(String sql, int parameters) {
    }

    private TdsSqlRewriter() {
    }

    static Rewritten rewrite(String sql) throws SQLException {
        StringBuilder out = new StringBuilder(sql.length() + 16); // seclume-allow: SQL text, never a secret
        int parameters = 0;
        int i = 0;
        int length = sql.length();
        while (i < length) {
            char c = sql.charAt(i);
            switch (c) {
                case '\'' -> i = copyQuoted(sql, i, '\'', '\'', out);
                case '"' -> i = copyQuoted(sql, i, '"', '"', out);
                case '[' -> i = copyQuoted(sql, i, '[', ']', out);
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
                    out.append("@P").append(parameters++);
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

    /**
     * Copies a literal or a bracketed identifier.
     *
     * <p>Doubling the closing character escapes it: {@code 'it''s'} and
     * {@code [a]]b]} are one literal and one identifier, not two.
     */
    private static int copyQuoted(String sql, int start, char open, char close,
                                  StringBuilder out) throws SQLException {
        out.append(open);
        int i = start + 1;
        while (i < sql.length()) {
            char c = sql.charAt(i);
            if (c == close) {
                out.append(c);
                if (i + 1 < sql.length() && sql.charAt(i + 1) == close) {
                    out.append(close);
                    i += 2;
                    continue;
                }
                return i + 1;
            }
            out.append(c);
            i++;
        }
        throw new SQLException("unterminated "
                + (open == '\'' ? "string literal" : "identifier") + " in: " + shape(sql));
    }

    private static int copyLineComment(String sql, int start, StringBuilder out) {
        int end = sql.indexOf('\n', start);
        if (end < 0) {
            out.append(sql, start, sql.length());
            return sql.length();
        }
        out.append(sql, start, end + 1);
        return end + 1;
    }

    /** T-SQL block comments nest - so this counts rather than searching. */
    private static int copyBlockComment(String sql, int start, StringBuilder out)
            throws SQLException {
        int depth = 0;
        int i = start;
        while (i < sql.length()) {
            if (sql.startsWith("/*", i)) {
                depth++;
                out.append("/*");
                i += 2;
            } else if (sql.startsWith("*/", i)) {
                depth--;
                out.append("*/");
                i += 2;
                if (depth == 0) {
                    return i;
                }
            } else {
                out.append(sql.charAt(i));
                i++;
            }
        }
        throw new SQLException("unterminated block comment in: " + shape(sql));
    }

    /**
     * A statement named in a message, with its values taken out.
     *
     * <p>The text must not travel: a literal in it can be a password, a card
     * number or a person, and an exception message is precisely what ends up
     * in a log. The shape says which statement it was and carries none of
     * that - see {@link space.seclume.QueryFingerprint}.
     */
    private static String shape(String sql) {
        return space.seclume.QueryFingerprint.of(sql,
                space.seclume.QueryFingerprint.Dialect.SQLSERVER);
    }

}
