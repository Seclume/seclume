package space.seclume.r2dbc;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * R2DBC's placeholders, which are each database's own, as JDBC's {@code ?}.
 *
 * <p>R2DBC leaves the placeholder syntax to the database: {@code $1} on
 * PostgreSQL, {@code ?} on MySQL, {@code @name} on SQL Server, {@code :name}
 * on Oracle - what each vendor's R2DBC driver takes, so that SQL written for
 * one of them runs here unchanged. The JDBC drivers underneath take {@code ?}
 * in order. This turns the one into the other and remembers which JDBC
 * positions each placeholder became: {@code $1} may appear twice, or after
 * {@code $2}.
 *
 * <p>Only code is rewritten: string literals, quoted identifiers, comments
 * and PostgreSQL's dollar-quoted bodies are copied as they are - a {@code $1}
 * inside a function body is not a parameter of this statement.
 */
final class Placeholders {

    /** The placeholder syntax of one database. */
    enum Dialect {
        POSTGRESQL, MYSQL, SQLSERVER, ORACLE;

        static Dialect of(String protocol) {
            return switch (protocol.toLowerCase(Locale.ROOT)) {
                case "postgresql", "postgres" -> POSTGRESQL;
                case "mysql", "mariadb" -> MYSQL;
                case "sqlserver", "mssql" -> SQLSERVER;
                case "oracle" -> ORACLE;
                default -> throw new IllegalArgumentException("no seclume driver for '"
                        + protocol + "' - postgresql, mysql, mariadb, sqlserver or oracle");
            };
        }

        /** From {@code DatabaseMetaData.getDatabaseProductName()}. */
        static Dialect ofProduct(String product) {
            String name = product == null ? "" : product.toLowerCase(Locale.ROOT);
            if (name.contains("postgres") || name.contains("cockroach") || name.contains("yugabyte")) {
                return POSTGRESQL;
            }
            if (name.contains("mysql") || name.contains("mariadb")) {
                return MYSQL;
            }
            if (name.contains("sql server")) {
                return SQLSERVER;
            }
            if (name.contains("oracle")) {
                return ORACLE;
            }
            throw new IllegalArgumentException("no placeholders known for '" + product + "'");
        }
    }

    /**
     * The JDBC text, and for each placeholder - by its name, in the order
     * of first appearance - the JDBC positions (1-based) it was turned into.
     */
    record Parsed(String sql, Map<String, int[]> positions, boolean compound) {

        int count() {
            int count = 0;
            for (int[] at : positions.values()) {
                count += at.length;
            }
            return count;
        }

        /** The placeholder bound by index {@code i}, R2DBC's 0-based one. */
        String nameOf(int index) {
            if (index < 0 || index >= positions.size()) {
                throw new IndexOutOfBoundsException("bind index " + index + " - the statement has "
                        + positions.size() + " parameter(s)");
            }
            return new ArrayList<>(positions.keySet()).get(index);
        }
    }

    private Placeholders() {
    }

    static Parsed parse(String sql, Dialect dialect) {
        StringBuilder out = new StringBuilder(sql.length());
        Map<String, List<Integer>> found = new LinkedHashMap<>();
        int position = 0;
        boolean compound = false;
        int i = 0;
        int n = sql.length();
        while (i < n) {
            char c = sql.charAt(i);
            int end = skipQuoted(sql, i, dialect);
            if (end > i) {
                out.append(sql, i, end);
                i = end;
                continue;
            }
            if (c == ';' && !sql.substring(i + 1).isBlank()) {
                compound = true;                     // a second statement follows
            }
            String name = null;
            int next = i + 1;
            if (dialect == Dialect.POSTGRESQL && c == '$' && i + 1 < n
                    && Character.isDigit(sql.charAt(i + 1))) {
                next = digitsEnd(sql, i + 1);
                name = sql.substring(i, next);                      // "$1"
            } else if (dialect == Dialect.MYSQL && c == '?') {
                name = Integer.toString(found.size());              // positional
            } else if (dialect == Dialect.SQLSERVER && c == '@' && i + 1 < n
                    && isNameStart(sql.charAt(i + 1)) && (i == 0 || sql.charAt(i - 1) != '@')) {
                next = nameEnd(sql, i + 1);
                name = sql.substring(i + 1, next).toLowerCase(Locale.ROOT);
            } else if (dialect == Dialect.ORACLE && c == ':' && i + 1 < n
                    && (isNameStart(sql.charAt(i + 1)) || Character.isDigit(sql.charAt(i + 1)))
                    && (i == 0 || sql.charAt(i - 1) != ':')) {
                next = nameEnd(sql, i + 1);
                name = sql.substring(i + 1, next).toLowerCase(Locale.ROOT);
            }
            if (name == null) {
                out.append(c);
                i++;
                continue;
            }
            out.append('?');
            found.computeIfAbsent(name, k -> new ArrayList<>()).add(++position);
            i = next;
        }
        Map<String, int[]> positions = new LinkedHashMap<>();
        if (dialect == Dialect.POSTGRESQL) {
            // $1, $2 ... by number, not by first appearance: bind(0) is $1
            // even where $2 is written first.
            found.entrySet().stream()
                    .sorted((a, b) -> byNumber(a.getKey().substring(1), b.getKey().substring(1)))
                    .forEach(e -> positions.put(e.getKey(), toArray(e.getValue())));
        } else {
            found.forEach((k, v) -> positions.put(k, toArray(v)));
        }
        return new Parsed(out.toString(), positions, compound);
    }

    /** The end of a literal, quoted identifier or comment at {@code i}, or {@code i}. */
    private static int skipQuoted(String sql, int i, Dialect dialect) {
        char c = sql.charAt(i);
        int n = sql.length();
        if (c == '\'' || c == '"' || (c == '`' && dialect == Dialect.MYSQL)) {
            int j = i + 1;
            while (j < n) {
                char d = sql.charAt(j);
                if (d == '\\' && dialect == Dialect.MYSQL && c != '`') {
                    j += 2;
                    continue;
                }
                if (d == c) {
                    if (j + 1 < n && sql.charAt(j + 1) == c) {
                        j += 2;                                  // doubled quote
                        continue;
                    }
                    return j + 1;
                }
                j++;
            }
            return n;
        }
        if (c == '[' && dialect == Dialect.SQLSERVER) {
            int close = sql.indexOf(']', i + 1);
            return close < 0 ? n : close + 1;
        }
        if (c == '-' && i + 1 < n && sql.charAt(i + 1) == '-') {
            int line = sql.indexOf('\n', i);
            return line < 0 ? n : line + 1;
        }
        if (c == '#' && dialect == Dialect.MYSQL) {
            int line = sql.indexOf('\n', i);
            return line < 0 ? n : line + 1;
        }
        if (c == '/' && i + 1 < n && sql.charAt(i + 1) == '*') {
            int close = sql.indexOf("*/", i + 2);
            return close < 0 ? n : close + 2;
        }
        if (c == '$' && dialect == Dialect.POSTGRESQL && i + 1 < n
                && !Character.isDigit(sql.charAt(i + 1))) {
            // $tag$ ... $tag$, or $$ ... $$
            int tagEnd = sql.indexOf('$', i + 1);
            if (tagEnd < 0) {
                return i;
            }
            String tag = sql.substring(i, tagEnd + 1);
            for (int k = 1; k < tag.length() - 1; k++) {
                if (!isNamePart(tag.charAt(k))) {
                    return i;                                     // not a tag
                }
            }
            int close = sql.indexOf(tag, tagEnd + 1);
            return close < 0 ? n : close + tag.length();
        }
        return i;
    }

    /** Two runs of digits by their value, however long: $99999999999 is no int. */
    private static int byNumber(String a, String b) {
        String x = a.replaceFirst("^0+(?=.)", "");
        String y = b.replaceFirst("^0+(?=.)", "");
        return x.length() != y.length() ? Integer.compare(x.length(), y.length()) : x.compareTo(y);
    }

    private static int digitsEnd(String sql, int from) {
        int j = from;
        while (j < sql.length() && Character.isDigit(sql.charAt(j))) {
            j++;
        }
        return j;
    }

    private static int nameEnd(String sql, int from) {
        int j = from;
        while (j < sql.length() && isNamePart(sql.charAt(j))) {
            j++;
        }
        return j;
    }

    private static boolean isNameStart(char c) {
        return Character.isLetter(c) || c == '_';
    }

    private static boolean isNamePart(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }

    private static int[] toArray(List<Integer> list) {
        int[] array = new int[list.size()];
        for (int i = 0; i < array.length; i++) {
            array[i] = list.get(i);
        }
        return array;
    }
}
