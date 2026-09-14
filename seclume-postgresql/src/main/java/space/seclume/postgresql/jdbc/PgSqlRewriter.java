package space.seclume.postgresql.jdbc;

import java.sql.SQLException;

/**
 * Translates JDBC's question marks into PostgreSQL's placeholders.
 *
 * <p>JDBC writes {@code where id = ?}, the server wants {@code where id = $1}.
 * This rewrite is the only intervention seclume makes on the SQL - and it has
 * to be exact, because a question mark does not mean the same thing
 * everywhere:
 *
 * <ul>
 *   <li>inside {@code 'text?'} it is text,</li>
 *   <li>inside {@code "column?"} it is part of an identifier,</li>
 *   <li>inside {@code $$...?...$$} it is text in a dollar quote,</li>
 *   <li>inside {@code -- ?} and {@code /* ? *&#47;} it is a comment,</li>
 *   <li>and {@code ?|}, {@code ?&} and {@code ??} are operators on
 *       {@code jsonb} and on geometries.</li>
 * </ul>
 *
 * <p>That is why this really reads rather than replaces. A
 * {@code String.replace} would be one line - and would destroy every question
 * mark in every text literal as soon as somebody writes one.
 */
final class PgSqlRewriter {

    /** The result: rewritten SQL and the number of placeholders. */
    record Rewritten(String sql, int parameters) {
    }

    private PgSqlRewriter() {
    }

    static Rewritten rewrite(String sql) throws SQLException {
        StringBuilder out = new StringBuilder(sql.length() + 16);
        int parameters = 0;
        int i = 0;
        int length = sql.length();
        while (i < length) {
            char c = sql.charAt(i);
            switch (c) {
                case '\'' -> i = copyQuoted(sql, i, '\'', out);
                case '"' -> i = copyQuoted(sql, i, '"', out);
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
                case '$' -> {
                    int end = dollarQuoteEnd(sql, i);
                    if (end < 0) {
                        out.append(c);
                        i++;
                    } else {
                        out.append(sql, i, end);
                        i = end;
                    }
                }
                case '?' -> {
                    // ?? is the escaped question mark, ?| and ?& are jsonb operators.
                    char next = i + 1 < length ? sql.charAt(i + 1) : '\0';
                    if (next == '?') {
                        out.append('?');
                        i += 2;
                    } else if (next == '|' || next == '&') {
                        out.append(c).append(next);
                        i += 2;
                    } else {
                        out.append('$').append(++parameters);
                        i++;
                    }
                }
                default -> {
                    out.append(c);
                    i++;
                }
            }
        }
        return new Rewritten(out.toString(), parameters);
    }

    /** Copies a literal or an identifier; doubling the character escapes it. */
    private static int copyQuoted(String sql, int start, char quote, StringBuilder out)
            throws SQLException {
        out.append(quote);
        int i = start + 1;
        while (i < sql.length()) {
            char c = sql.charAt(i);
            if (c == quote) {
                out.append(c);
                if (i + 1 < sql.length() && sql.charAt(i + 1) == quote) {
                    out.append(quote);
                    i += 2;
                    continue;
                }
                return i + 1;
            }
            // A backslash only escapes inside E'...'; outside it is a
            // character like any other. This loop copies both unchanged.
            out.append(c);
            i++;
        }
        throw new SQLException("unterminated " + (quote == '\'' ? "string literal" : "identifier")
                + " in: " + sql);
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

    /** Block comments nest in PostgreSQL - unlike in C. */
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
        throw new SQLException("unterminated block comment in: " + sql);
    }

    /**
     * The end of a dollar quote {@code $tag$ ... $tag$}, or -1 if none starts
     * at this position at all (then {@code $} is part of {@code $1} or of an
     * identifier, say).
     */
    private static int dollarQuoteEnd(String sql, int start) {
        int i = start + 1;
        while (i < sql.length() && (Character.isLetterOrDigit(sql.charAt(i))
                || sql.charAt(i) == '_')) {
            // A digit right after the dollar means $1 - not a quote.
            if (i == start + 1 && Character.isDigit(sql.charAt(i))) {
                return -1;
            }
            i++;
        }
        if (i >= sql.length() || sql.charAt(i) != '$') {
            return -1;
        }
        String tag = sql.substring(start, i + 1);
        int end = sql.indexOf(tag, i + 1);
        return end < 0 ? -1 : end + tag.length();
    }
}
