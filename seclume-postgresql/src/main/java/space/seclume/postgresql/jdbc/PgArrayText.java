package space.seclume.postgresql.jdbc;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * The text form of a PostgreSQL array, taken apart.
 *
 * <p>The server writes an array as <code>{1,2,3}</code>, nested ones as
 * <code>{{1,2},{3,4}}</code>, and it quotes an element whenever the element
 * would otherwise be ambiguous - when it contains a comma, a brace, a quote, a
 * backslash, leading or trailing whitespace, or when it reads as the word
 * {@code NULL}. Inside quotes, a backslash escapes the next character. An
 * <b>unquoted</b> {@code NULL}, in any case, is the null element; a quoted
 * {@code "NULL"} is the four-letter string.
 *
 * <p>That last distinction is the whole reason this is a parser and not a
 * {@code split(",")}. Getting it wrong turns a row of user data into a null
 * silently, which is the failure mode this project exists to avoid.
 *
 * <p>A non-default delimiter is possible in principle - {@code box} uses a
 * semicolon and is the only built-in type that does - so the delimiter is a
 * parameter rather than a comma baked into the code.
 *
 * <p>What comes back is a tree of {@code List}: a one-dimensional array is a
 * list of {@code String} (or {@code null}), a two-dimensional one a list of
 * those lists. Converting the strings to the element type is
 * {@link PgArray}'s business, because only it knows the type.
 */
final class PgArrayText {

    private final String text;
    private final char delimiter;
    private int at;

    private PgArrayText(String text, char delimiter) {
        this.text = text;
        this.delimiter = delimiter;
    }

    /**
     * Parses the whole literal.
     *
     * @return a nested {@code List} whose leaves are {@code String} or {@code null}
     */
    static List<Object> parse(String text, char delimiter) throws SQLException {
        PgArrayText parser = new PgArrayText(text.trim(), delimiter);
        // An array with an explicit lower bound arrives as "[1:3]={...}": the
        // dimensions come first, then an equals sign. JDBC has no way to carry a
        // lower bound other than 1, so the prefix is read and dropped rather than
        // being mistaken for an element.
        if (parser.peek() == '[') {
            int equals = parser.text.indexOf('=', parser.at);
            if (equals < 0) {
                throw malformed(text);
            }
            parser.at = equals + 1;
        }
        if (parser.peek() != '{') {
            throw malformed(text);
        }
        List<Object> value = parser.readBraces();
        parser.skipSpace();
        if (parser.at != parser.text.length()) {
            throw malformed(text);
        }
        return value;
    }

    private List<Object> readBraces() throws SQLException {
        expect('{');
        List<Object> elements = new ArrayList<>();
        skipSpace();
        if (peek() == '}') {
            at++;
            return elements;
        }
        while (true) {
            skipSpace();
            elements.add(peek() == '{' ? readBraces() : readElement());
            skipSpace();
            char next = next();
            if (next == '}') {
                return elements;
            }
            if (next != delimiter) {
                throw malformed(text);
            }
        }
    }

    /** One element: quoted, or unquoted and then possibly the null marker. */
    private String readElement() throws SQLException {
        if (peek() == '"') {
            at++;
            StringBuilder value = new StringBuilder();
            while (true) {
                char c = next();
                if (c == '"') {
                    return value.toString();
                }
                value.append(c == '\\' ? next() : c);
            }
        }
        int start = at;
        while (at < text.length()) {
            char c = text.charAt(at);
            if (c == delimiter || c == '}' || c == '{') {
                break;
            }
            at++;
        }
        String raw = text.substring(start, at).trim();
        return raw.equalsIgnoreCase("NULL") ? null : raw;
    }

    private void skipSpace() {
        while (at < text.length() && Character.isWhitespace(text.charAt(at))) {
            at++;
        }
    }

    private char peek() {
        return at < text.length() ? text.charAt(at) : '\0';
    }

    private char next() throws SQLException {
        if (at >= text.length()) {
            throw malformed(text);
        }
        return text.charAt(at++);
    }

    private void expect(char c) throws SQLException {
        if (next() != c) {
            throw malformed(text);
        }
    }

    /**
     * The literal is not quoted back, and that is deliberate.
     *
     * <p>It is a row: whatever the application stored, which can be a name, a
     * token or a number somebody would rather not see in a log - and an
     * exception message is where logs come from. The length and where the
     * parse stopped are enough to find the row; the content is not this
     * exception's to publish.
     */
    private static SQLException malformed(String text) {
        return new SQLException("not a PostgreSQL array literal ("
                + (text == null ? 0 : text.length()) + " characters)", "22P02");
    }
}
