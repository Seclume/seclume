package space.seclume.internal.jdbc;

import java.math.BigDecimal;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * A whole list bound to one placeholder: {@code where id in (?)} with
 * {@code setObject(1, List.of(...))}.
 *
 * <p>Every list length used to be a statement of its own - a plan of its own
 * on the server, an entry of its own in every cache - and the lists ran into
 * limits: SQL Server takes 2100 parameters, Oracle 1000 expressions in a list
 * (ORA-01795). Here the list is <b>one value</b>, and the statement text does
 * not depend on its length:
 *
 * <table>
 *   <caption>{@code x in (?)} with a list of numbers</caption>
 *   <tr><td>PostgreSQL</td><td>{@code x = any(cast(? as bigint[]))}</td></tr>
 *   <tr><td>MySQL</td><td>{@code x in (select v from json_table(?, '$[*]' columns (v bigint path '$')) as seclume_in)}</td></tr>
 *   <tr><td>SQL Server</td><td>{@code x in (select v from openjson(?) with (v bigint '$'))}</td></tr>
 *   <tr><td>Oracle</td><td>{@code x in (select v from json_table(?, '$[*]' columns (v number path '$')))}</td></tr>
 * </table>
 *
 * <p>The element type decides the column type: whole numbers, decimals (with
 * the precision and scale the values need), strings and UUIDs. MySQL's
 * strings go through {@code json_unquote}, which is coercible like a
 * parameter - a typed column would carry the connection's collation and
 * clash with the compared column's. {@code not in (?)} works, and so does an
 * empty list: {@code in} matches nothing and {@code not in} everything, which
 * a literal {@code in ()} cannot even express. A null element is refused,
 * because {@code not in} with a null in it matches nothing, silently.
 */
public final class InLists {

    /** The four spellings. */
    public enum Dialect { POSTGRESQL, MYSQL, SQLSERVER, ORACLE }

    /** What the elements are. */
    public enum Kind { INTEGER, DECIMAL, TEXT, UUID }

    /**
     * One list, ready to bind.
     *
     * @param payload   the single value that goes over the wire - a JSON array,
     *                  or on PostgreSQL an array literal
     * @param precision for decimals, the digits the values need
     * @param scale     for decimals, the digits after the point
     */
    public record Bound(Kind kind, String payload, int precision, int scale) {
    }

    private InLists() {
    }

    /**
     * {@code lists} with {@code list} noted under {@code index} - grown when
     * needed, and left null as long as no list was ever bound.
     */
    public static Bound[] note(Bound[] lists, int index, Bound list) {
        if (list == null && (lists == null || index >= lists.length)) {
            return lists;
        }
        Bound[] noted = lists == null || index >= lists.length
                ? java.util.Arrays.copyOf(lists == null ? new Bound[0] : lists,
                        Math.max(index + 1, 8))
                : lists;
        noted[index] = list;
        return noted;
    }

    /** Whether any list is bound. */
    public static boolean any(Bound[] lists) {
        if (lists != null) {
            for (Bound list : lists) {
                if (list != null) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Refuses a list in a batch: each row could need a statement of another shape. */
    public static void refuseInBatch(Bound[] lists) throws SQLException {
        if (any(lists)) {
            throw new java.sql.SQLFeatureNotSupportedException("a list bound to in (?) cannot "
                    + "go into a batch: each row could need a statement of its own shape");
        }
    }

    /** Whether {@code value} is a list to be bound as one - a collection or an object array. */
    public static boolean isList(Object value) {
        return value instanceof Collection<?> || value instanceof Object[];
    }

    /**
     * The list as one value for {@code dialect}, or {@code null} when
     * {@code value} is not a list.
     */
    public static Bound of(Object value, Dialect dialect) throws SQLException {
        if (!isList(value)) {
            return null;
        }
        List<Object> elements = new ArrayList<>();
        if (value instanceof Collection<?> collection) {
            elements.addAll(collection);
        } else {
            elements.addAll(java.util.Arrays.asList((Object[]) value));
        }
        Kind kind = null;
        int integerDigits = 1;
        int scale = 0;
        List<String> texts = new ArrayList<>(elements.size());
        for (Object element : elements) {
            if (element == null) {
                throw new SQLException("a list bound to in (?) holds a null - refused, because "
                        + "not in with a null in it matches no row at all", "22004");
            }
            Kind own;
            String text;
            if (element instanceof Long || element instanceof Integer
                    || element instanceof Short || element instanceof Byte) {
                own = Kind.INTEGER;
                text = element.toString();
            } else if (element instanceof java.math.BigInteger big) { // seclume-allow: a list value an application bound, never a secret
                own = big.bitLength() < 64 ? Kind.INTEGER : Kind.DECIMAL;
                text = big.toString();
            } else if (element instanceof BigDecimal || element instanceof Double
                    || element instanceof Float) {
                BigDecimal decimal = element instanceof BigDecimal d ? d
                        : BigDecimal.valueOf(((Number) element).doubleValue());
                if (element instanceof Double d && (d.isNaN() || d.isInfinite())
                        || element instanceof Float f && (f.isNaN() || f.isInfinite())) {
                    throw new SQLException("a list bound to in (?) holds " + element
                            + ", which no database column can equal", "22003");
                }
                own = Kind.DECIMAL;
                text = decimal.toPlainString();
            } else if (element instanceof CharSequence || element instanceof Character) {
                own = Kind.TEXT;
                text = element.toString();
            } else if (element instanceof UUID) {
                own = Kind.UUID;
                text = element.toString();
            } else {
                throw new SQLException("a list bound to in (?) may hold whole numbers, decimals, "
                        + "strings or UUIDs - not " + element.getClass().getName(), "22023");
            }
            if (own == Kind.DECIMAL || own == Kind.INTEGER) {
                BigDecimal number = new BigDecimal(text);
                int ownScale = Math.max(number.scale(), 0);
                scale = Math.max(scale, ownScale);
                integerDigits = Math.max(integerDigits, number.precision() - number.scale());
            }
            kind = merge(kind, own);
            texts.add(text);
        }
        if (kind == null) {
            kind = Kind.INTEGER;                    // empty: any type does, this one is cheapest
        }
        int precision = integerDigits + scale;
        if (kind == Kind.DECIMAL) {
            int most = dialect == Dialect.MYSQL ? 65 : 38;
            if (dialect != Dialect.POSTGRESQL && dialect != Dialect.ORACLE && precision > most) {
                throw new SQLException("a list bound to in (?) needs " + precision
                        + " digits, more than the " + most + " this server's decimal has", "22003");
            }
        }
        String payload = dialect == Dialect.POSTGRESQL ? arrayLiteral(kind, texts) : json(kind, texts);
        return new Bound(kind, payload, precision, scale);
    }

    private static Kind merge(Kind so, Kind now) throws SQLException {
        if (so == null || so == now) {
            return now;
        }
        if ((so == Kind.INTEGER || so == Kind.DECIMAL) && (now == Kind.INTEGER || now == Kind.DECIMAL)) {
            return Kind.DECIMAL;
        }
        throw new SQLException("a list bound to in (?) mixes " + so.name().toLowerCase(Locale.ROOT)
                + " and " + now.name().toLowerCase(Locale.ROOT) + " elements", "22023");
    }

    private static String json(Kind kind, List<String> texts) {
        StringBuilder out = new StringBuilder(texts.size() * 8 + 2); // seclume-allow: list values an application bound, not a secret
        out.append('[');
        for (int i = 0; i < texts.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            if (kind == Kind.INTEGER || kind == Kind.DECIMAL) {
                out.append(texts.get(i));
            } else {
                quoteJson(out, texts.get(i));
            }
        }
        return out.append(']').toString();
    }

    private static void quoteJson(StringBuilder out, String text) {
        out.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    private static String arrayLiteral(Kind kind, List<String> texts) {
        StringBuilder out = new StringBuilder(texts.size() * 8 + 2); // seclume-allow: list values an application bound, not a secret
        out.append('{');
        for (int i = 0; i < texts.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            if (kind == Kind.TEXT) {
                // Quoted always: an unquoted NULL, a blank or a comma would
                // mean something else inside the braces.
                out.append('"');
                String text = texts.get(i);
                for (int c = 0; c < text.length(); c++) {
                    char ch = text.charAt(c);
                    if (ch == '"' || ch == '\\') {
                        out.append('\\');
                    }
                    out.append(ch);
                }
                out.append('"');
            } else {
                out.append(texts.get(i));
            }
        }
        return out.append('}').toString();
    }

    /**
     * {@code sql} with every placeholder that has a list in {@code lists}
     * (one-based, {@code null} for an ordinary value) turned into the
     * dialect's form. The number and order of the placeholders stays the
     * same, so the values bind as they were set.
     *
     * @throws SQLException when a list is bound to a placeholder that is not
     *                      the whole of an {@code in (?)}
     */
    public static String apply(String sql, Bound[] lists, Dialect dialect) throws SQLException {
        if (lists == null) {
            return sql;
        }
        int[] offsets = CallSyntax.placeholderOffsets(sql);
        boolean[] code = CallSyntax.codeMask(sql);
        StringBuilder out = null; // seclume-allow: statement text, no values in it
        int copied = 0;
        for (int index = 1; index < lists.length && index <= offsets.length; index++) {
            Bound list = lists[index];
            if (list == null) {
                continue;
            }
            int at = offsets[index - 1];
            int open = back(sql, code, at - 1);
            int close = forward(sql, code, at + 1);
            if (open < 0 || sql.charAt(open) != '(' || close >= sql.length()
                    || sql.charAt(close) != ')') {
                throw notInList(index);
            }
            int inEnd = back(sql, code, open - 1) + 1;
            int inStart = inEnd - 2;
            // "in" has to be code - an "in" at the end of a comment in front
            // of the bracket is not the operator.
            if (inStart < 0 || !code[inStart] || !code[inStart + 1]
                    || !sql.regionMatches(true, inStart, "in", 0, 2)
                    || inStart > 0 && Character.isLetterOrDigit(sql.charAt(inStart - 1))) {
                throw notInList(index);
            }
            int notEnd = back(sql, code, inStart - 1) + 1;
            boolean negated = notEnd >= 3 && sql.regionMatches(true, notEnd - 3, "not", 0, 3)
                    && code[notEnd - 3]
                    && (notEnd == 3 || !Character.isLetterOrDigit(sql.charAt(notEnd - 4)));
            if (out == null) {
                out = new StringBuilder(sql.length() + 96); // seclume-allow: statement text, no values in it
            }
            if (dialect == Dialect.POSTGRESQL) {
                int from = negated ? notEnd - 3 : inStart;
                out.append(sql, copied, from)
                        .append(negated ? "<> all(cast(? as " : "= any(cast(? as ")
                        .append(postgresType(list)).append("[]))");
            } else {
                out.append(sql, copied, open).append('(').append(subquery(list, dialect))
                        .append(')');
            }
            copied = close + 1;
        }
        if (out == null) {
            return sql;
        }
        return out.append(sql, copied, sql.length()).toString();
    }

    private static String postgresType(Bound list) {
        return switch (list.kind()) {
            case INTEGER -> "bigint";
            case DECIMAL -> "numeric";
            case TEXT -> "text";
            case UUID -> "uuid";
        };
    }

    private static String subquery(Bound list, Dialect dialect) {
        String decimal = "decimal(" + list.precision() + "," + list.scale() + ")";
        return switch (dialect) {
            case MYSQL -> switch (list.kind()) {
                case INTEGER -> "select v from json_table(?, '$[*]' columns (v bigint path '$')) as seclume_in";
                case DECIMAL -> "select v from json_table(?, '$[*]' columns (v " + decimal
                        + " path '$')) as seclume_in";
                case TEXT, UUID -> "select json_unquote(v) from json_table(?, '$[*]' columns "
                        + "(v json path '$')) as seclume_in";
            };
            case SQLSERVER -> "select v from openjson(?) with (v " + switch (list.kind()) {
                case INTEGER -> "bigint";
                case DECIMAL -> decimal;
                case TEXT -> "nvarchar(max)";
                case UUID -> "uniqueidentifier";
            } + " '$')";
            case ORACLE -> "select v from json_table(?, '$[*]' columns (v " + switch (list.kind()) {
                case INTEGER, DECIMAL -> "number";
                case TEXT -> "varchar2(4000)";
                case UUID -> "varchar2(36)";
            } + " path '$'))";
            case POSTGRESQL -> throw new IllegalStateException("PostgreSQL uses = any");
        };
    }

    /** The last code position before {@code at} that is not blank - comments skipped - or -1. */
    private static int back(String sql, boolean[] code, int at) {
        while (at >= 0 && (!code[at] || Character.isWhitespace(sql.charAt(at)))) {
            at--;
        }
        return at;
    }

    /** The first code position from {@code at} on that is not blank - comments skipped. */
    private static int forward(String sql, boolean[] code, int at) {
        while (at < sql.length() && (!code[at] || Character.isWhitespace(sql.charAt(at)))) {
            at++;
        }
        return at;
    }

    private static SQLException notInList(int index) {
        return new SQLException("parameter " + index + " is a list, and a list binds only to "
                + "a placeholder that stands alone in an in (...): where x in (?)", "22023");
    }
}
