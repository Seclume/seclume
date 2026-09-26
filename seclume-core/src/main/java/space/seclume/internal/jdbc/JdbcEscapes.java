package space.seclume.internal.jdbc;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * JDBC's escape syntax, turned into what the server understands.
 *
 * <p>{@code {fn ucase(x)}}, {@code {d '2026-09-23'}}, {@code {ts '...'}},
 * {@code {t '...'}}, {@code like ... {escape '!'}} and {@code {oj ...}} - the
 * portable spellings JDBC defines and requires a driver to process by default.
 * This driver used to refuse them outright and pass SQL through untouched,
 * which held on SQL Server (it speaks ODBC escapes itself) and mostly on MySQL,
 * and on PostgreSQL and Oracle turned every one into a syntax error from the
 * server. pgjdbc, ojdbc and Connector/J all translate them; a drop-in
 * replacement that does not is not one.
 *
 * <p><b>What is translated depends on the server</b>, and the rule is to touch
 * as little as possible: SQL Server gets the text unchanged, MySQL only the
 * {@code escape} clause it does not parse, PostgreSQL and Oracle everything.
 * A statement without a brace costs one {@code indexOf}.
 *
 * <p>Braces inside string literals, quoted identifiers, comments and
 * PostgreSQL's dollar quotes are left alone - {@code '{1,2}'} is an array
 * literal, not an escape. A brace that does not open a known escape is left
 * alone too. {@code {call ...}} is not handled here: it belongs to
 * {@code prepareCall}, which has its own translation.
 */
public final class JdbcEscapes {

    /** Which server the text is going to. */
    public enum Dialect {
        POSTGRESQL, MYSQL, SQLSERVER, ORACLE
    }

    private JdbcEscapes() {
    }

    /** The text, with every escape this server cannot read translated. */
    public static String translate(String sql, Dialect dialect) {
        if (sql == null || sql.indexOf('{') < 0 || dialect == Dialect.SQLSERVER) {
            return sql;
        }
        return new Translation(sql, dialect).run();
    }

    private static final class Translation {

        private final String sql;
        private final Dialect dialect;
        private int at;

        Translation(String sql, Dialect dialect) {
            this.sql = sql;
            this.dialect = dialect;
        }

        String run() {
            StringBuilder out = new StringBuilder(sql.length());
            copyUntil(out, -1);
            return out.toString();
        }

        /**
         * Copies from {@link #at} until the closing brace that ends the
         * current escape ({@code depth >= 0}) or the end of the text,
         * translating escapes on the way.
         */
        private void copyUntil(StringBuilder out, int depth) {
            while (at < sql.length()) {
                char c = sql.charAt(at);
                if (c == '\'' || c == '"' || (c == '`' && dialect == Dialect.MYSQL)) {
                    copyQuoted(out, c);
                } else if (c == '-' && next('-')) {
                    copyTo(out, sql.indexOf('\n', at));
                } else if (c == '/' && next('*')) {
                    int end = sql.indexOf("*/", at + 2);
                    copyTo(out, end < 0 ? -1 : end + 2);
                } else if (c == '$' && dialect == Dialect.POSTGRESQL && copyDollarQuoted(out)) {
                    // copied
                } else if (c == '{') {
                    if (!escape(out)) {
                        out.append(c);
                        at++;
                    }
                } else if (c == '}' && depth >= 0) {
                    at++;
                    return;
                } else {
                    out.append(c);
                    at++;
                }
            }
        }

        private boolean next(char c) {
            return at + 1 < sql.length() && sql.charAt(at + 1) == c;
        }

        private void copyTo(StringBuilder out, int end) {
            int stop = end < 0 ? sql.length() : end;
            out.append(sql, at, stop);
            at = stop;
        }

        /** A literal or quoted identifier, doubled quotes included. */
        private void copyQuoted(StringBuilder out, char quote) {
            int i = at + 1;
            while (i < sql.length()) {
                char c = sql.charAt(i);
                if (c == '\\' && quote == '\'' && dialect == Dialect.MYSQL && i + 1 < sql.length()) {
                    i += 2;
                    continue;
                }
                if (c == quote) {
                    if (i + 1 < sql.length() && sql.charAt(i + 1) == quote) {
                        i += 2;
                        continue;
                    }
                    i++;
                    break;
                }
                i++;
            }
            out.append(sql, at, i);
            at = i;
        }

        /** {@code $$ ... $$} or {@code $tag$ ... $tag$}. */
        private boolean copyDollarQuoted(StringBuilder out) {
            int close = sql.indexOf('$', at + 1);
            if (close < 0) {
                return false;
            }
            String tag = sql.substring(at, close + 1);
            if (!tag.matches("\\$[A-Za-z_]?[A-Za-z0-9_]*\\$")) {
                return false;
            }
            int end = sql.indexOf(tag, close + 1);
            copyTo(out, end < 0 ? -1 : end + tag.length());
            return true;
        }

        /** One escape at {@link #at}; false if the brace opens none. */
        private boolean escape(StringBuilder out) {
            int i = at + 1;
            while (i < sql.length() && Character.isWhitespace(sql.charAt(i))) {
                i++;
            }
            int wordEnd = i;
            while (wordEnd < sql.length() && Character.isLetter(sql.charAt(wordEnd))) {
                wordEnd++;
            }
            String word = sql.substring(i, wordEnd).toLowerCase(Locale.ROOT);
            if (wordEnd == sql.length() || !Character.isWhitespace(sql.charAt(wordEnd))) {
                return false;
            }
            switch (word) {
                case "fn", "d", "t", "ts", "escape", "oj" -> {
                }
                default -> {
                    return false;
                }
            }
            if (dialect == Dialect.MYSQL && !word.equals("escape")) {
                return false;       // MySQL parses the others itself
            }
            at = wordEnd;
            StringBuilder body = new StringBuilder();
            copyUntil(body, 0);
            String inner = body.toString().strip();
            out.append(switch (word) {
                case "fn" -> function(inner);
                case "d" -> literal("DATE", inner);
                case "t" -> dialect == Dialect.ORACLE
                        ? "TO_DATE(" + inner + ", 'HH24:MI:SS')" : literal("TIME", inner);
                case "ts" -> literal("TIMESTAMP", inner);
                case "escape" -> "ESCAPE " + inner;
                default -> inner;                          // oj: the join as written
            });
            return true;
        }

        private static String literal(String type, String quoted) {
            return type + " " + quoted;
        }

        /** {@code name(args)} - the name mapped, the arguments already translated. */
        private String function(String call) {
            int open = call.indexOf('(');
            if (open < 0 || !call.endsWith(")")) {
                return call;
            }
            String name = call.substring(0, open).strip().toLowerCase(Locale.ROOT);
            List<String> args = arguments(call.substring(open + 1, call.length() - 1));
            boolean oracle = dialect == Dialect.ORACLE;
            return switch (name) {
                case "ucase" -> "UPPER(" + join(args) + ")";
                case "lcase" -> "LOWER(" + join(args) + ")";
                case "concat" -> oracle && args.size() == 2
                        ? "CONCAT(" + join(args) + ")" : "(" + String.join(" || ", args) + ")";
                case "length" -> "LENGTH(" + join(args) + ")";
                case "substring" -> "SUBSTR(" + join(args) + ")";
                case "locate" -> args.size() == 2
                        ? (oracle ? "INSTR(" + args.get(1) + ", " + args.get(0) + ")"
                                : "STRPOS(" + args.get(1) + ", " + args.get(0) + ")")
                        : call;
                case "ifnull" -> "COALESCE(" + join(args) + ")";
                case "ceiling" -> "CEIL(" + join(args) + ")";
                case "log" -> "LN(" + join(args) + ")";
                case "now" -> "CURRENT_TIMESTAMP";
                case "curdate", "current_date" -> "CURRENT_DATE";
                case "curtime", "current_time" -> oracle ? "CURRENT_TIMESTAMP" : "CURRENT_TIME";
                case "database" -> oracle ? "SYS_CONTEXT('USERENV', 'DB_NAME')"
                        : "CURRENT_DATABASE()";
                case "user" -> oracle ? "USER" : "CURRENT_USER";
                case "year", "month", "hour", "minute", "second" ->
                        "EXTRACT(" + name.toUpperCase(Locale.ROOT) + " FROM " + join(args) + ")";
                case "dayofmonth" -> "EXTRACT(DAY FROM " + join(args) + ")";
                default -> call;          // the same name on the server, as pgjdbc does
            };
        }

        private static String join(List<String> args) {
            return String.join(", ", args);
        }

        /** Top-level commas only - {@code f(a, g(b, c))} has two arguments. */
        private static List<String> arguments(String text) {
            List<String> args = new ArrayList<>();
            int depth = 0;
            int start = 0;
            char quote = 0;
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (quote != 0) {
                    if (c == quote) {
                        quote = 0;
                    }
                } else if (c == '\'' || c == '"') {
                    quote = c;
                } else if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    depth--;
                } else if (c == ',' && depth == 0) {
                    args.add(text.substring(start, i).strip());
                    start = i + 1;
                }
            }
            String last = text.substring(start).strip();
            if (!last.isEmpty() || !args.isEmpty()) {
                args.add(last);
            }
            return args;
        }
    }
}
