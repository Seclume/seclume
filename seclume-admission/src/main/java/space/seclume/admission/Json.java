package space.seclume.admission;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The JSON an admission webhook reads and writes: objects as
 * {@link LinkedHashMap}s in their order, arrays as lists, strings,
 * {@link Boolean}s, {@code null}, and numbers as {@link Number} - their text,
 * written back exactly as read.
 *
 * <p>An {@code AdmissionReview} is the API server's, not an attacker's, but
 * it is read defensively all the same: nesting deeper than
 * {@value #DEEPEST} and anything after the value are refused.
 */
final class Json {

    /** Deeper than any pod; deep enough that a stack is never at risk. */
    static final int DEEPEST = 128;

    /** A number as it was written. */
    record Number(String text) {
    }

    private final String text;
    private int at;

    private Json(String text) {
        this.text = text;
    }

    /** The value {@code text} holds. */
    static Object parse(String text) {
        Json json = new Json(text);
        json.space();
        Object value = json.value(0);
        json.space();
        if (json.at != text.length()) {
            throw json.error("text after the value");
        }
        return value;
    }

    private IllegalArgumentException error(String what) {
        return new IllegalArgumentException("not JSON as expected: " + what + " at character "
                + at);
    }

    private void space() {
        while (at < text.length()) {
            char c = text.charAt(at);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                return;
            }
            at++;
        }
    }

    private Object value(int depth) {
        if (depth > DEEPEST) {
            throw error("nesting deeper than " + DEEPEST);
        }
        if (at >= text.length()) {
            throw error("the end where a value belongs");
        }
        char c = text.charAt(at);
        return switch (c) {
            case '{' -> object(depth);
            case '[' -> array(depth);
            case '"' -> string();
            case 't' -> word("true", Boolean.TRUE);
            case 'f' -> word("false", Boolean.FALSE);
            case 'n' -> word("null", null);
            default -> number();
        };
    }

    private Object word(String word, Object value) {
        if (!text.startsWith(word, at)) {
            throw error("an unknown word");
        }
        at += word.length();
        return value;
    }

    private Map<String, Object> object(int depth) {
        Map<String, Object> object = new LinkedHashMap<>();
        at++;
        space();
        if (at < text.length() && text.charAt(at) == '}') {
            at++;
            return object;
        }
        while (true) {
            space();
            if (at >= text.length() || text.charAt(at) != '"') {
                throw error("a name that is not a string");
            }
            String name = string();
            space();
            expect(':');
            space();
            object.put(name, value(depth + 1));
            space();
            if (at < text.length() && text.charAt(at) == ',') {
                at++;
                continue;
            }
            expect('}');
            return object;
        }
    }

    private List<Object> array(int depth) {
        List<Object> array = new ArrayList<>();
        at++;
        space();
        if (at < text.length() && text.charAt(at) == ']') {
            at++;
            return array;
        }
        while (true) {
            space();
            array.add(value(depth + 1));
            space();
            if (at < text.length() && text.charAt(at) == ',') {
                at++;
                continue;
            }
            expect(']');
            return array;
        }
    }

    private void expect(char c) {
        if (at >= text.length() || text.charAt(at) != c) {
            throw error("something other than '" + c + "'");
        }
        at++;
    }

    private String string() {
        at++;
        StringBuilder out = new StringBuilder();
        while (true) {
            if (at >= text.length()) {
                throw error("a string without its end");
            }
            char c = text.charAt(at++);
            if (c == '"') {
                return out.toString();
            }
            if (c < 0x20) {
                throw error("a control character in a string");
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (at >= text.length()) {
                throw error("an escape without its character");
            }
            char escaped = text.charAt(at++);
            switch (escaped) {
                case '"', '\\', '/' -> out.append(escaped);
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    if (at + 4 > text.length()) {
                        throw error("a unicode escape cut short");
                    }
                    int unit = 0;
                    for (int i = 0; i < 4; i++) {
                        int digit = Character.digit(text.charAt(at + i), 16);
                        if (digit < 0) {
                            throw error("a unicode escape that is not hexadecimal");
                        }
                        unit = unit * 16 + digit;
                    }
                    at += 4;
                    out.append((char) unit);
                }
                default -> throw error("an unknown escape");
            }
        }
    }

    private Number number() {
        int start = at;
        if (at < text.length() && text.charAt(at) == '-') {
            at++;
        }
        int digits = digits();
        if (digits == 0) {
            throw error("an unexpected character");
        }
        if (at < text.length() && text.charAt(at) == '.') {
            at++;
            if (digits() == 0) {
                throw error("a fraction without digits");
            }
        }
        if (at < text.length() && (text.charAt(at) == 'e' || text.charAt(at) == 'E')) {
            at++;
            if (at < text.length() && (text.charAt(at) == '+' || text.charAt(at) == '-')) {
                at++;
            }
            if (digits() == 0) {
                throw error("an exponent without digits");
            }
        }
        return new Number(text.substring(start, at));
    }

    private int digits() {
        int start = at;
        while (at < text.length() && text.charAt(at) >= '0' && text.charAt(at) <= '9') {
            at++;
        }
        return at - start;
    }

    /** {@code value} as JSON text. */
    static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(value, out);
        return out.toString();
    }

    private static void write(Object value, StringBuilder out) {
        switch (value) {
            case null -> out.append("null");
            case Boolean b -> out.append(b);
            case Number n -> out.append(n.text());
            case Integer i -> out.append(i);
            case Long l -> out.append(l);
            case String s -> string(s, out);
            case Map<?, ?> map -> {
                out.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    string(String.valueOf(entry.getKey()), out);
                    out.append(':');
                    write(entry.getValue(), out);
                }
                out.append('}');
            }
            case List<?> list -> {
                out.append('[');
                for (int i = 0; i < list.size(); i++) {
                    if (i > 0) {
                        out.append(',');
                    }
                    write(list.get(i), out);
                }
                out.append(']');
            }
            default -> throw new IllegalArgumentException("no JSON for a value of type "
                    + value.getClass().getName());
        }
    }

    private static void string(String s, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    // ---- navigation, for the shapes of a pod

    /** {@code value} as an object, or an empty one when it is none. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> asObject(Object value) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    /** {@code value} as an array, or an empty one when it is none. */
    @SuppressWarnings("unchecked")
    static List<Object> asArray(Object value) {
        return value instanceof List<?> list ? (List<Object>) list : List.of();
    }

    /** {@code value} as a string, or {@code null}. */
    static String asString(Object value) {
        return value instanceof String s ? s : null;
    }
}
