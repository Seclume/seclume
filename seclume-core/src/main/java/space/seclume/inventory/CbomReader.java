package space.seclume.inventory;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import space.seclume.inventory.CryptoInventory.Asset;
import space.seclume.inventory.CryptoInventory.Kind;

/**
 * A CBOM {@link CycloneDxCbom} wrote, read back into the inventory's assets -
 * so that a policy, a quantum readiness report or a comparison can be run on
 * a file a build kept, not only on the running process.
 *
 * <p>Only the components seclume wrote are taken: those with a
 * {@code seclume:kind} property. A CBOM is no secret - it holds facts, never
 * values - so it is read as ordinary text; the parser is a small, strict one
 * for JSON (RFC 8259), with a depth limit, since a CBOM handed to a pipeline
 * is input like any other.
 */
public final class CbomReader {

    /** Nesting deeper than this is refused rather than followed. */
    static final int MAX_DEPTH = 64;

    private CbomReader() {
    }

    /** The assets in {@code json}; anything that is not a CycloneDX document is refused. */
    public static List<Asset> read(String json) {
        Object document = new Parser(json).document();
        if (!(document instanceof Map<?, ?> root) || !"CycloneDX".equals(root.get("bomFormat"))) {
            throw new IllegalArgumentException("not a CycloneDX document (no \"bomFormat\": "
                    + "\"CycloneDX\")");
        }
        List<Asset> assets = new ArrayList<>();
        if (!(root.get("components") instanceof List<?> components)) {
            return assets;
        }
        for (Object component : components) {
            if (!(component instanceof Map<?, ?> map)) {
                continue;
            }
            Map<String, String> properties = properties(map.get("properties"));
            String kind = properties.remove("seclume:kind");
            if (kind == null) {
                continue;
            }
            Kind k;
            try {
                k = Kind.valueOf(kind.toUpperCase(java.util.Locale.ROOT).replace('-', '_'));
            } catch (IllegalArgumentException e) {
                continue;
            }
            String algorithm = properties.remove("seclume:algorithm");
            int bits = CryptoInventory.number(properties.remove("seclume:bits"));
            String source = properties.remove("seclume:source");
            Instant first = instant(properties.remove("seclume:first-seen"));
            Instant last = instant(properties.remove("seclume:last-used"));
            Instant expires = instant(properties.remove("seclume:expires"));
            String uses = properties.remove("seclume:uses");
            Map<String, String> facts = new LinkedHashMap<>();
            for (Map.Entry<String, String> property : properties.entrySet()) {
                if (property.getKey().startsWith("seclume:")) {
                    facts.put(property.getKey().substring("seclume:".length()), property.getValue());
                }
            }
            if (expires == null && k == Kind.CERTIFICATE) {
                expires = certificateExpiry(map);
            }
            assets.add(new Asset(text(map.get("bom-ref")), k, text(map.get("name")), algorithm,
                    bits, source, first == null ? Instant.EPOCH : first,
                    last == null ? Instant.EPOCH : last, longOf(uses), expires, Map.copyOf(facts)));
        }
        return assets;
    }

    private static Instant certificateExpiry(Map<?, ?> component) {
        if (component.get("cryptoProperties") instanceof Map<?, ?> crypto
                && crypto.get("certificateProperties") instanceof Map<?, ?> certificate) {
            return instant(text(certificate.get("notValidAfter")));
        }
        return null;
    }

    private static Map<String, String> properties(Object list) {
        Map<String, String> properties = new LinkedHashMap<>();
        if (list instanceof List<?> entries) {
            for (Object entry : entries) {
                if (entry instanceof Map<?, ?> property && property.get("name") instanceof String name) {
                    String value = text(property.get("value"));
                    properties.put(name, value == null ? "" : value);
                }
            }
        }
        return properties;
    }

    private static String text(Object value) {
        return value instanceof String s ? s : value == null ? null : value.toString();
    }

    private static Instant instant(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static long longOf(String text) {
        if (text == null) {
            return 0;
        }
        try {
            return Long.parseLong(text.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /** JSON into maps, lists, strings, numbers (as {@code Double} or {@code Long}), booleans and null. */
    static final class Parser {

        private final String text;
        private int at;

        Parser(String text) {
            if (text == null) {
                throw new IllegalArgumentException("no JSON to read - the CBOM is null");
            }
            this.text = text;
        }

        Object document() {
            Object value = value(0);
            blank();
            if (at != text.length()) {
                throw error("text after the document");
            }
            return value;
        }

        private Object value(int depth) {
            if (depth > MAX_DEPTH) {
                throw error("nested deeper than " + MAX_DEPTH);
            }
            blank();
            if (at >= text.length()) {
                throw error("the document ends early");
            }
            char c = text.charAt(at);
            return switch (c) {
                case '{' -> object(depth);
                case '[' -> array(depth);
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> {
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        yield number();
                    }
                    throw error("unexpected '" + c + "'");
                }
            };
        }

        private Map<String, Object> object(int depth) {
            Map<String, Object> map = new LinkedHashMap<>();
            at++;
            blank();
            if (peek() == '}') {
                at++;
                return map;
            }
            while (true) {
                blank();
                if (peek() != '"') {
                    throw error("a key is a string");
                }
                String key = string();
                blank();
                expect(':');
                map.put(key, value(depth + 1));
                blank();
                char c = next();
                if (c == '}') {
                    return map;
                }
                if (c != ',') {
                    throw error("',' or '}' expected");
                }
            }
        }

        private List<Object> array(int depth) {
            List<Object> list = new ArrayList<>();
            at++;
            blank();
            if (peek() == ']') {
                at++;
                return list;
            }
            while (true) {
                list.add(value(depth + 1));
                blank();
                char c = next();
                if (c == ']') {
                    return list;
                }
                if (c != ',') {
                    throw error("',' or ']' expected");
                }
            }
        }

        private String string() {
            at++;
            StringBuilder out = new StringBuilder();
            while (true) {
                if (at >= text.length()) {
                    throw error("a string is not closed");
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
                char e = next();
                switch (e) {
                    case '"', '\\', '/' -> out.append(e);
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (at + 4 > text.length()) {
                            throw error("a \\u escape is cut short");
                        }
                        int code = 0;
                        for (int i = 0; i < 4; i++) {
                            int d = Character.digit(text.charAt(at++), 16);
                            if (d < 0) {
                                throw error("a \\u escape is not hex");
                            }
                            code = code * 16 + d;
                        }
                        out.append((char) code);
                    }
                    default -> throw error("an unknown escape \\" + e);
                }
            }
        }

        private Object number() {
            int start = at;
            if (peek() == '-') {
                at++;
            }
            if (peek() == '0') {
                at++;
            } else if (Character.isDigit(peek())) {
                while (Character.isDigit(peek())) {
                    at++;
                }
            } else {
                throw error("a number has no digits");
            }
            boolean integral = true;
            if (peek() == '.') {
                integral = false;
                at++;
                if (!Character.isDigit(peek())) {
                    throw error("a fraction has no digits");
                }
                while (Character.isDigit(peek())) {
                    at++;
                }
            }
            if (peek() == 'e' || peek() == 'E') {
                integral = false;
                at++;
                if (peek() == '+' || peek() == '-') {
                    at++;
                }
                if (!Character.isDigit(peek())) {
                    throw error("an exponent has no digits");
                }
                while (Character.isDigit(peek())) {
                    at++;
                }
            }
            String digits = text.substring(start, at);
            if (integral && digits.length() < 19) {
                return Long.parseLong(digits);
            }
            return Double.parseDouble(digits);
        }

        private Object literal(String word, Object value) {
            if (!text.startsWith(word, at)) {
                throw error("unexpected text");
            }
            at += word.length();
            return value;
        }

        private void blank() {
            while (at < text.length()) {
                char c = text.charAt(at);
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                    return;
                }
                at++;
            }
        }

        private char peek() {
            return at < text.length() ? text.charAt(at) : '\0';
        }

        private char next() {
            if (at >= text.length()) {
                throw error("the document ends early");
            }
            return text.charAt(at++);
        }

        private void expect(char c) {
            if (next() != c) {
                throw error("'" + c + "' expected");
            }
        }

        private IllegalArgumentException error(String what) {
            return new IllegalArgumentException("not valid JSON at offset " + at + ": " + what);
        }
    }
}
