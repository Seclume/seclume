package space.seclume;

import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;

/**
 * The connection was lost while a COMMIT was in flight, and nobody knows
 * whether the transaction was committed.
 *
 * <p>This is the third outcome of a commit, and the one most libraries blur
 * into the second. A commit that <b>succeeded</b> returns. A commit the server
 * <b>refused</b> throws with the server's own state, and the transaction is
 * gone. But a commit whose answer never arrived - the socket closed, a node
 * went away, a load balancer dropped the connection - may have been applied
 * or may not, and the client cannot tell which from where it stands. The
 * server may have written the commit record a microsecond before the network
 * failed.
 *
 * <p>Reporting that as an ordinary connection failure invites the worst
 * response to it: run the transaction again. If the first one committed, the
 * booking now exists twice. So it gets a type of its own, and the state SQL
 * reserves for exactly this case - {@code 08007}, <i>transaction resolution
 * unknown</i> - so that code and frameworks can branch on it by either.
 *
 * <p><b>What to do with one</b> is the application's decision, because only
 * the application knows how to ask: look for the row the transaction wrote, a
 * request id it stored, an idempotency key. {@link Retry} never repeats one,
 * and nothing in this library ever will.
 *
 * <p><b>When it is thrown.</b> Whenever a connection fails after the driver
 * began sending a COMMIT - from {@code commit()} and from
 * {@code setAutoCommit(true)} with a transaction open, which JDBC defines as
 * a commit - and whenever it fails under a <b>write in auto-commit mode</b>,
 * which commits itself and is the same situation with the COMMIT left
 * implicit. A failure <i>before</i> sending is not this: the driver knew the
 * connection was gone, nothing was sent, and the server rolls back an
 * abandoned transaction. A failure to write is this, because a write that
 * fails may still have delivered every byte - TCP says nothing either way.
 *
 * <p>The message carries no statement text and nothing from the transaction,
 * for the same reason no exception here does.
 */
public final class TransactionResolutionUnknownException extends SQLNonTransientConnectionException {

    private static final long serialVersionUID = 1L;

    /** The standard state: connection exception, transaction resolution unknown. */
    public static final String SQL_STATE = "08007";

    public TransactionResolutionUnknownException(String message, Throwable cause) {
        super(message, SQL_STATE, cause);
    }

    /**
     * What a failure under a statement in auto-commit mode means.
     *
     * <p>In auto-commit every statement is its own transaction and commits
     * itself, so a write whose answer was lost is exactly as unknown as a
     * lost COMMIT. A statement that <b>only reads</b> is left as it was: a
     * lost answer to a {@code select} changed nothing, and calling it
     * "possibly applied" would send somebody looking for a write that cannot
     * exist.
     *
     * <p>Which statements read is decided by the first keyword, and the
     * decision leans towards "unknown" wherever it is unsure - see
     * {@link #onlyReads}. A statement that is wrongly called a write costs a
     * check that finds nothing; one wrongly called a read would be repeated
     * and done twice.
     *
     * @param sql the statement, or {@code null} for a batch - which JDBC
     *            defines as updates, so a batch is always a write
     */
    public static SQLException duringAutoCommit(SQLException failure, String sql) {
        if (failure instanceof TransactionResolutionUnknownException) {
            return failure;
        }
        String state = failure.getSQLState();
        if (state == null || !state.startsWith("08")) {
            return failure;
        }
        if (sql != null && onlyReads(sql)) {
            return failure;
        }
        return new TransactionResolutionUnknownException(
                "the connection was lost while a statement in auto-commit mode was in flight. "
                        + "It commits itself, so whether it was applied is not known - the "
                        + "server may have done it. Check for what it wrote before running it "
                        + "again",
                failure);
    }

    /**
     * Whether a statement can be trusted to have written nothing.
     *
     * <p>Deliberately narrow, and every doubt is resolved towards "it may
     * write":
     *
     * <ul>
     *   <li>{@code select}, {@code show}, {@code explain}, {@code describe},
     *       {@code desc}, {@code values} read - unless the text contains
     *       {@code into}, because {@code select ... into} creates a table on
     *       PostgreSQL and SQL Server and writes a file on MySQL;</li>
     *   <li>{@code with} reads only if none of {@code insert}, {@code update},
     *       {@code delete}, {@code merge} or {@code into} appears as a word -
     *       PostgreSQL's data-modifying common table expressions start with
     *       {@code with} as well;</li>
     *   <li>everything else - {@code call}, {@code exec}, an anonymous block,
     *       anything not recognised - may write.</li>
     * </ul>
     *
     * <p>A word inside a string literal counts too, which can only make a
     * read look like a write. That is the harmless direction. The case that
     * remains is a {@code select} calling a function that writes; it reads as
     * a read here, and the CHANGELOG says so.
     */
    static boolean onlyReads(String sql) {
        String text = sql.toLowerCase(java.util.Locale.ROOT);
        int at = skipNoise(text, 0);
        int end = at;
        while (end < text.length() && Character.isLetter(text.charAt(end))) {
            end++;
        }
        String first = text.substring(at, end);
        return switch (first) {
            case "values" -> !hasWord(text, "into");
            case "select" -> !hasWord(text, "into") && !callsSomethingUnknown(text);
            case "show", "explain", "describe", "desc" -> true;
            case "with" -> !hasWord(text, "insert") && !hasWord(text, "update")
                    && !hasWord(text, "delete") && !hasWord(text, "merge")
                    && !hasWord(text, "into") && !callsSomethingUnknown(text);
            default -> false;
        };
    }

    /**
     * Whether the statement calls a function that is not known to be pure.
     *
     * <p>A function can write, and in auto-commit whatever it wrote is
     * committed with the statement. On PostgreSQL {@code select
     * create_order(42)} is the ordinary way to call one that does something;
     * {@code select archive(id) from orders} does it once per row. Neither
     * can be told apart from a read without asking the catalogue, and asking
     * it on the failure path of a connection that has just broken is not an
     * option.
     *
     * <p>So the rule is turned round: a call reads only when it is to a
     * <b>built-in function known to have no side effects</b> - the
     * aggregates, the string, number and date functions, the window
     * functions. Anything else - every function somebody wrote - may write.
     * The list can only be wrong in one direction: a pure function missing
     * from it costs a needless check, never a repeated write.
     *
     * <p>The first version of this rule looked only at statements without a
     * table and left {@code select archive(id) from orders} as a read. That
     * gap was named, and then closed here.
     */
    private static boolean callsSomethingUnknown(String text) {
        for (int open = text.indexOf('('); open >= 0; open = text.indexOf('(', open + 1)) {
            int end = open;
            while (end > 0 && Character.isWhitespace(text.charAt(end - 1))) {
                end--;
            }
            int start = end;
            while (start > 0 && isWordChar(text.charAt(start - 1))) {
                start--;
            }
            if (start == end || Character.isDigit(text.charAt(start))) {
                continue;                               // a parenthesis that only groups
            }
            String name = text.substring(start, end);
            if (GROUPING.contains(name)) {
                continue;
            }
            // A qualified name - app.archive(...) - is somebody's function
            // whatever it is called.
            boolean qualified = start > 0 && text.charAt(start - 1) == '.';
            if (qualified || !PURE.contains(name)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Built-in functions that read and compute and write nothing.
     *
     * <p>Names shared by the four databases or common to at least one of
     * them. Deliberately without {@code nextval}, {@code setval},
     * {@code pg_advisory_lock}, {@code get_lock}, {@code sleep} and anything
     * of that kind: they are built in and they do something.
     */
    private static final java.util.Set<String> PURE = java.util.Set.of(
            // aggregates
            "count", "sum", "avg", "min", "max", "stddev", "variance", "string_agg",
            "array_agg", "json_agg", "jsonb_agg", "group_concat", "listagg", "bool_and",
            "bool_or", "every",
            // window functions
            "row_number", "rank", "dense_rank", "ntile", "lag", "lead", "first_value",
            "last_value", "nth_value", "percent_rank", "cume_dist",
            // strings
            "lower", "upper", "length", "char_length", "character_length", "octet_length",
            "substring", "substr", "trim", "ltrim", "rtrim", "btrim", "concat", "concat_ws",
            "replace", "position", "strpos", "instr", "left", "right", "lpad", "rpad",
            "reverse", "initcap", "split_part", "regexp_replace", "regexp_substr",
            "regexp_matches", "format", "len", "charindex", "nvl", "nvl2", "decode",
            // numbers
            "abs", "round", "trunc", "floor", "ceil", "ceiling", "mod", "power", "sqrt",
            "exp", "ln", "log", "sign", "greatest", "least",
            // conditionals and conversion
            "coalesce", "nullif", "cast", "convert", "isnull", "ifnull", "iif", "to_char",
            "to_number", "to_date", "to_timestamp",
            // dates and times
            "now", "current_date", "current_timestamp", "localtimestamp", "sysdate",
            "systimestamp", "getdate", "sysdatetime", "date_trunc", "date_part", "extract",
            "datediff", "dateadd", "datepart", "age", "date_format", "add_months",
            // json
            "json_build_object", "jsonb_build_object", "json_extract", "json_value",
            "json_query", "jsonb_extract_path", "json_object");

    /** Words a parenthesis follows without anything being called. */
    private static final java.util.Set<String> GROUPING = java.util.Set.of(
            "select", "union", "intersect", "except", "all", "distinct", "in", "exists",
            "values", "and", "or", "not", "on", "as", "any", "some", "where", "when", "then",
            "else", "case", "by", "with", "lateral", "is",
            // window and query syntax: over (...), from (subquery), join (...)
            "over", "filter", "within", "partition", "from", "join", "using", "having",
            "group", "order", "limit", "offset", "fetch", "top", "between", "like");

    /** Past whitespace, comments and opening parentheses. */
    private static int skipNoise(String text, int at) {
        while (at < text.length()) {
            char c = text.charAt(at);
            if (Character.isWhitespace(c) || c == '(') {
                at++;
            } else if (text.startsWith("--", at)) {
                int line = text.indexOf('\n', at);
                at = line < 0 ? text.length() : line + 1;
            } else if (text.startsWith("/*", at)) {
                int close = text.indexOf("*/", at + 2);
                at = close < 0 ? text.length() : close + 2;
            } else {
                break;
            }
        }
        return at;
    }

    private static boolean hasWord(String text, String word) {
        int from = 0;
        while (true) {
            int found = text.indexOf(word, from);
            if (found < 0) {
                return false;
            }
            boolean before = found == 0 || !isWordChar(text.charAt(found - 1));
            int after = found + word.length();
            boolean behind = after >= text.length() || !isWordChar(text.charAt(after));
            if (before && behind) {
                return true;
            }
            from = found + 1;
        }
    }

    private static boolean isWordChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }

    /**
     * What a failure during a commit means.
     *
     * <p>A failure of the connection becomes this exception, with the original
     * as its cause. Anything else - the server refused the commit, a deferred
     * constraint was violated - is returned unchanged: the server answered,
     * so the outcome is known, and it is "not committed".
     *
     * <p>For the drivers; public because they live in other modules.
     */
    public static SQLException duringCommit(SQLException failure) {
        if (failure instanceof TransactionResolutionUnknownException) {
            return failure;
        }
        String state = failure.getSQLState();
        if (state == null || !state.startsWith("08")) {
            return failure;
        }
        return new TransactionResolutionUnknownException(
                "the connection was lost while COMMIT was in flight, so whether the "
                        + "transaction was committed is not known. The server may have applied "
                        + "it. Check for what it wrote before running it again - repeating it "
                        + "blindly is how the same work gets done twice",
                failure);
    }
}
