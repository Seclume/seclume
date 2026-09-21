package space.seclume;

/**
 * A statement with its values taken out, so that it can be named in a log, a
 * metric or a trace without any of them travelling with it.
 *
 * <pre>
 * select * from customer where id = 42 and name = 'alice'
 * select * from customer where id = ? and name = ?
 * </pre>
 *
 * <p>Slow-query analysis wants to group statements, and grouping needs a name
 * that is the same for every execution. The obvious name is the SQL text -
 * and the SQL text is the one thing that must not be recorded, because a
 * literal in it can be a password, a card number or a person. The obvious
 * alternative, a hash of the text, is useless to read and still groups
 * nothing, since every distinct value hashes differently.
 *
 * <p>So: the shape is kept and every value is removed. The result is readable,
 * groups correctly, and carries nothing.
 *
 * <p><b>The rule this is written to.</b> Ambiguity resolves towards masking,
 * always. Where a dialect makes it unclear whether something is an identifier
 * or a literal - {@code "text"} in MySQL is a string, in PostgreSQL a column -
 * the uncertain case is replaced rather than kept. A fingerprint that loses a
 * column name is a worse fingerprint; a fingerprint that keeps a password is
 * a leak with a nice interface.
 *
 * <p>Note what this is not: it is not a parser and not a validator. It never
 * refuses, because its callers are logging code, and logging code that throws
 * on a statement the database was perfectly happy with turns an observability
 * feature into an outage.
 *
 * <p>What it removes: string literals of every quoting form the dialect has,
 * numeric literals, JDBC {@code ?}, and the server-side placeholder spellings
 * ({@code $1}, {@code :name}, {@code @p1}). What it keeps: keywords,
 * identifiers, operators and structure. What it collapses: runs of
 * whitespace, comments, and lists of placeholders - {@code in (?, ?, ?)}
 * becomes {@code in (?)}, so that the same query with three values and with
 * three hundred is one entry rather than two.
 */
public final class QueryFingerprint {

    /**
     * Which quoting rules apply.
     *
     * <p>The differences that matter are all about what counts as a string.
     * Everything else is decoration.
     */
    public enum Dialect {

        /** Dollar quotes, {@code E'...'}, nested block comments. */
        POSTGRESQL,

        /**
         * Backtick identifiers, {@code #} comments, backslash escapes - and
         * {@code "..."} is a <b>string</b> unless {@code ANSI_QUOTES} is set,
         * which cannot be known from here, so it is masked.
         */
        MYSQL,

        /** {@code [bracket]} identifiers and {@code N'...'}. */
        SQLSERVER,

        /** {@code q'[...]'} alternative quoting. */
        ORACLE,

        /**
         * No dialect known: every quoting form of every dialect is treated as
         * a string. Loses identifier names and loses nothing else.
         */
        GENERIC
    }

    private static final int MAX_LENGTH = 4096;

    private QueryFingerprint() {
    }

    /** The fingerprint under generic rules - safe anywhere, least readable. */
    public static String of(String sql) {
        return of(sql, Dialect.GENERIC);
    }

    /**
     * The fingerprint of a statement.
     *
     * @return the masked, whitespace-normalised text; never null, and never
     *         longer than four kilobytes - a statement past that length is
     *         truncated with a marker, because the point is to name a query
     *         and not to store it
     */
    public static String of(String sql, Dialect dialect) {
        if (sql == null || sql.isEmpty()) {
            return "";
        }
        StringBuilder out = new StringBuilder(Math.min(sql.length(), MAX_LENGTH) + 8);
        int i = 0;
        int length = sql.length();
        while (i < length) {
            char c = sql.charAt(i);
            if (Character.isWhitespace(c)) {
                appendSpace(out);
                i++;
            } else if (c == '\'') {
                i = skipQuoted(sql, i, '\'');
                appendValue(out);
            } else if (c == '"') {
                if (dialect == Dialect.POSTGRESQL || dialect == Dialect.ORACLE
                        || dialect == Dialect.SQLSERVER) {
                    i = copyQuoted(sql, i, '"', out);
                } else {
                    // MySQL without ANSI_QUOTES, and the generic case: a
                    // string. Not knowing is the same as it being one.
                    i = skipQuoted(sql, i, '"');
                    appendValue(out);
                }
            } else if (c == '`') {
                if (dialect == Dialect.MYSQL) {
                    i = copyQuoted(sql, i, '`', out);
                } else {
                    i = skipQuoted(sql, i, '`');
                    appendValue(out);
                }
            } else if (c == '[' && (dialect == Dialect.SQLSERVER || dialect == Dialect.GENERIC)) {
                int end = sql.indexOf(']', i);
                if (end < 0) {
                    appendValue(out);
                    i = length;
                } else if (dialect == Dialect.SQLSERVER) {
                    out.append(sql, i, end + 1);
                    i = end + 1;
                } else {
                    appendValue(out);
                    i = end + 1;
                }
            } else if (c == '-' && i + 1 < length && sql.charAt(i + 1) == '-') {
                i = endOfLine(sql, i);
                appendSpace(out);
            } else if (c == '#' && dialect == Dialect.MYSQL) {
                i = endOfLine(sql, i);
                appendSpace(out);
            } else if (c == '/' && i + 1 < length && sql.charAt(i + 1) == '*') {
                i = endOfBlockComment(sql, i, dialect == Dialect.POSTGRESQL);
                appendSpace(out);
            } else if (c == '$' && dialect == Dialect.POSTGRESQL) {
                int end = dollarQuoteEnd(sql, i);
                if (end >= 0) {
                    i = end;
                    appendValue(out);
                } else {
                    // $1, $2 - a placeholder, which is already a value-shaped hole.
                    i = skipWhile(sql, i + 1, Character::isDigit);
                    appendValue(out);
                }
            } else if (c == ':' && i + 1 < length && isNameStart(sql.charAt(i + 1))) {
                i = skipWhile(sql, i + 1, QueryFingerprint::isNamePart);
                appendValue(out);
            } else if (c == '@' && i + 1 < length && isNameStart(sql.charAt(i + 1))
                    && dialect == Dialect.SQLSERVER) {
                i = skipWhile(sql, i + 1, QueryFingerprint::isNamePart);
                appendValue(out);
            } else if (c == '?') {
                i++;
                appendValue(out);
            } else if (isDigit(c) || (c == '.' && i + 1 < length && isDigit(sql.charAt(i + 1)))) {
                i = endOfNumber(sql, i);
                appendValue(out);
            } else if (isNameStart(c)) {
                int end = skipWhile(sql, i, QueryFingerprint::isNamePart);
                i = word(sql, i, end, dialect, out);
            } else {
                out.append(c);
                i++;
            }
            if (out.length() > MAX_LENGTH) {
                out.setLength(MAX_LENGTH);
                out.append(" ...");
                return out.toString().strip();
            }
        }
        return out.toString().strip();
    }

    /**
     * A stable number for the same shape, for a metric label or an index.
     *
     * <p>FNV-1a over the fingerprint. Not cryptographic and not meant to be:
     * it groups executions of one statement, and the thing it is computed
     * from has already had every value taken out of it, so there is nothing
     * in it to protect.
     */
    public static long idOf(String sql, Dialect dialect) {
        String fingerprint = of(sql, dialect);
        long hash = 0xcbf29ce484222325L;
        for (int i = 0; i < fingerprint.length(); i++) {
            hash ^= fingerprint.charAt(i);
            hash *= 0x100000001b3L;
        }
        return hash;
    }

    // ------------------------------------------------------------ the pieces --

    /**
     * A word: either a keyword and identifier to keep, or the start of a
     * prefixed literal to throw away.
     *
     * <p>{@code E'...'}, {@code N'...'}, {@code X'...'}, {@code B'...'} and
     * Oracle's {@code q'[...]'} all look like an identifier followed by a
     * string, and all of them are one literal. Missing that would emit the
     * prefix and then mask the value, which is harmless - but {@code q'}
     * would then be left with its body unrecognised, and that is not.
     */
    private static int word(String sql, int start, int end, Dialect dialect, StringBuilder out) {
        String text = sql.substring(start, end);
        boolean quoteFollows = end < sql.length() && sql.charAt(end) == '\'';
        if (quoteFollows && isLiteralPrefix(text, dialect)) {
            if (text.equalsIgnoreCase("q") || text.equalsIgnoreCase("nq")) {
                int after = oracleQuoteEnd(sql, end);
                appendValue(out);
                return after;
            }
            int after = skipQuoted(sql, end, '\'');
            appendValue(out);
            return after;
        }
        // Lower case so that SELECT and select are one fingerprint. Quoted
        // identifiers keep their case, because there it is significant.
        out.append(text.toLowerCase(java.util.Locale.ROOT));
        return end;
    }

    private static boolean isLiteralPrefix(String text, Dialect dialect) {
        return switch (text.toLowerCase(java.util.Locale.ROOT)) {
            case "e", "u&" -> dialect == Dialect.POSTGRESQL || dialect == Dialect.GENERIC;
            case "n" -> true;
            case "x", "b" -> true;
            case "q", "nq" -> dialect == Dialect.ORACLE || dialect == Dialect.GENERIC;
            default -> false;
        };
    }

    /**
     * Appends a value hole, collapsing a run of them.
     *
     * <p>{@code in (?, ?, ?)} becomes {@code in (?)}. Without this the same
     * query with a different number of values is a different fingerprint,
     * which is exactly the grouping failure the whole thing exists to avoid -
     * and it is the shape that produces thousands of one-off entries in
     * practice.
     */
    private static void appendValue(StringBuilder out) {
        int at = out.length() - 1;
        while (at >= 0 && (out.charAt(at) == ' ' || out.charAt(at) == ',')) {
            at--;
        }
        if (at >= 0 && out.charAt(at) == '?') {
            out.setLength(at + 1);
            return;
        }
        out.append('?');
    }

    private static void appendSpace(StringBuilder out) {
        if (out.length() > 0 && out.charAt(out.length() - 1) != ' ') {
            out.append(' ');
        }
    }

    /** Past a quoted run, doubling being the escape; unterminated runs to the end. */
    private static int skipQuoted(String sql, int start, char quote) {
        int i = start + 1;
        while (i < sql.length()) {
            char c = sql.charAt(i);
            if (c == '\\' && i + 1 < sql.length()) {
                // Only some dialects honour this, and treating it as an escape
                // everywhere can only make the masked run longer - never
                // shorter, which is the direction that would leak.
                i += 2;
                continue;
            }
            if (c == quote) {
                if (i + 1 < sql.length() && sql.charAt(i + 1) == quote) {
                    i += 2;
                    continue;
                }
                return i + 1;
            }
            i++;
        }
        return sql.length();
    }

    private static int copyQuoted(String sql, int start, char quote, StringBuilder out) {
        int end = skipQuoted(sql, start, quote);
        out.append(sql, start, end);
        return end;
    }

    private static int endOfLine(String sql, int start) {
        int end = sql.indexOf('\n', start);
        return end < 0 ? sql.length() : end + 1;
    }

    private static int endOfBlockComment(String sql, int start, boolean nesting) {
        int depth = 0;
        int i = start;
        while (i < sql.length()) {
            if (sql.startsWith("/*", i)) {
                depth++;
                i += 2;
                if (!nesting) {
                    depth = 1;
                }
            } else if (sql.startsWith("*/", i)) {
                depth--;
                i += 2;
                if (depth <= 0) {
                    return i;
                }
            } else {
                i++;
            }
        }
        return sql.length();
    }

    /** {@code $tag$ ... $tag$}, or -1 when the dollar is something else. */
    private static int dollarQuoteEnd(String sql, int start) {
        int i = start + 1;
        if (i < sql.length() && isDigit(sql.charAt(i))) {
            return -1;                        // $1 is a placeholder
        }
        while (i < sql.length() && (Character.isLetterOrDigit(sql.charAt(i))
                || sql.charAt(i) == '_')) {
            i++;
        }
        if (i >= sql.length() || sql.charAt(i) != '$') {
            return -1;
        }
        String tag = sql.substring(start, i + 1);
        int end = sql.indexOf(tag, i + 1);
        return end < 0 ? sql.length() : end + tag.length();
    }

    /**
     * Oracle's {@code q'[ ... ]'}, where the delimiter is whatever follows
     * the quote and brackets pair up.
     */
    private static int oracleQuoteEnd(String sql, int quoteAt) {
        if (quoteAt + 1 >= sql.length()) {
            return sql.length();
        }
        char open = sql.charAt(quoteAt + 1);
        char close = switch (open) {
            case '[' -> ']';
            case '(' -> ')';
            case '{' -> '}';
            case '<' -> '>';
            default -> open;
        };
        int end = sql.indexOf(close + "'", quoteAt + 2);
        return end < 0 ? sql.length() : end + 2;
    }

    private static int endOfNumber(String sql, int start) {
        int i = start;
        boolean exponent = false;
        while (i < sql.length()) {
            char c = sql.charAt(i);
            if (isDigit(c) || c == '.' || c == 'x' || c == 'X'
                    || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                i++;
            } else if ((c == 'e' || c == 'E') && !exponent) {
                exponent = true;
                i++;
            } else if ((c == '+' || c == '-') && i > start
                    && (sql.charAt(i - 1) == 'e' || sql.charAt(i - 1) == 'E')) {
                i++;
            } else {
                break;
            }
        }
        return i;
    }

    private static int skipWhile(String sql, int start, CharTest test) {
        int i = start;
        while (i < sql.length() && test.matches(sql.charAt(i))) {
            i++;
        }
        return i;
    }

    @FunctionalInterface
    private interface CharTest {
        boolean matches(char c);
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static boolean isNameStart(char c) {
        return Character.isLetter(c) || c == '_';
    }

    private static boolean isNamePart(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '$' || c == '#';
    }
}
