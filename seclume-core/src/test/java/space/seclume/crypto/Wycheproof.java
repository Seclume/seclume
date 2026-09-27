package space.seclume.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Project Wycheproof's test vectors, read from {@code src/test/resources/wycheproof}.
 *
 * <p>Wycheproof (https://github.com/C2SP/wycheproof) is a collection of test
 * cases written by people hunting for implementation bugs: tags off by a bit,
 * key sizes at the edge, points that are not on the curve, output lengths one
 * past the limit. Our own tests check what we thought of; these check what
 * others found in other libraries. The files are copied unchanged, see
 * {@code README.md} next to them for the commit they come from.
 *
 * <p>Every test case carries a {@link Result}: {@code valid} must be accepted
 * and give the stated output, {@code invalid} must be rejected, and
 * {@code acceptable} may go either way - but if it is accepted, the output
 * must still be the stated one.
 *
 * <p>The JSON is read by a few lines here rather than a library: seclume-core
 * has no dependencies, and the files use a small, fixed subset of JSON.
 */
final class Wycheproof {

    private Wycheproof() {
    }

    enum Result {
        VALID, INVALID, ACCEPTABLE
    }

    /**
     * One test case together with the attributes of its group (key size, tag
     * size, curve and so on), so a test sees everything in one place.
     */
    record Vector(String file, Map<String, Object> group, Map<String, Object> test) {

        int tcId() {
            return ((Number) test.get("tcId")).intValue();
        }

        Result result() {
            return Result.valueOf(string("result").toUpperCase(java.util.Locale.ROOT));
        }

        String string(String name) {
            Object value = test.containsKey(name) ? test.get(name) : group.get(name);
            if (!(value instanceof String s)) {
                throw new IllegalArgumentException(file + " #" + tcId() + ": no string " + name);
            }
            return s;
        }

        long number(String name) {
            Object value = test.containsKey(name) ? test.get(name) : group.get(name);
            if (!(value instanceof Number n)) {
                throw new IllegalArgumentException(file + " #" + tcId() + ": no number " + name);
            }
            return n.longValue();
        }

        byte[] bytes(String name) {
            return HexFormat.of().parseHex(string(name));
        }

        /** The hex field as a native segment - the form seclume's primitives take. */
        MemorySegment segment(Arena arena, String name) {
            byte[] bytes = bytes(name);
            MemorySegment segment = arena.allocate(Math.max(bytes.length, 1)).asSlice(0, bytes.length);
            MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return segment;
        }

        @Override
        public String toString() {
            String comment = test.get("comment") instanceof String s && !s.isEmpty() ? " " + s : "";
            return file + " #" + tcId() + " " + string("result") + comment;
        }
    }

    /** All test cases of one file, in file order. */
    @SuppressWarnings("unchecked")
    static List<Vector> load(String file) {
        Map<String, Object> root;
        try (InputStream in = Wycheproof.class.getResourceAsStream("/wycheproof/" + file)) {
            if (in == null) {
                throw new IllegalStateException("missing test resource wycheproof/" + file);
            }
            root = (Map<String, Object>) new Parser(new String(in.readAllBytes(),
                    StandardCharsets.UTF_8)).document();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        List<Vector> vectors = new ArrayList<>();
        for (Object g : (List<Object>) root.get("testGroups")) {
            Map<String, Object> group = (Map<String, Object>) g;
            for (Object t : (List<Object>) group.get("tests")) {
                vectors.add(new Vector(file, group, (Map<String, Object>) t));
            }
        }
        Number declared = (Number) root.get("numberOfTests");
        if (declared != null && declared.intValue() != vectors.size()) {
            throw new IllegalStateException(file + " declares " + declared + " tests, has "
                    + vectors.size());
        }
        return vectors;
    }

    /** Objects, arrays, strings, integers, true/false/null - what the files use. */
    private static final class Parser {

        private final String text;
        private int at;

        Parser(String text) {
            this.text = text;
        }

        Object document() {
            Object value = value();
            skipSpace();
            if (at != text.length()) {
                throw error("trailing content");
            }
            return value;
        }

        private Object value() {
            skipSpace();
            if (at >= text.length()) {
                throw error("unexpected end");
            }
            char c = text.charAt(at);
            return switch (c) {
                case '{' -> object();
                case '[' -> array();
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> number();
            };
        }

        private Map<String, Object> object() {
            Map<String, Object> map = new LinkedHashMap<>();
            at++;
            skipSpace();
            if (peek() == '}') {
                at++;
                return map;
            }
            while (true) {
                skipSpace();
                String key = string();
                skipSpace();
                expect(':');
                map.put(key, value());
                skipSpace();
                if (peek() == ',') {
                    at++;
                } else {
                    expect('}');
                    return map;
                }
            }
        }

        private List<Object> array() {
            List<Object> list = new ArrayList<>();
            at++;
            skipSpace();
            if (peek() == ']') {
                at++;
                return list;
            }
            while (true) {
                list.add(value());
                skipSpace();
                if (peek() == ',') {
                    at++;
                } else {
                    expect(']');
                    return list;
                }
            }
        }

        private String string() {
            expect('"');
            StringBuilder out = new StringBuilder();
            while (true) {
                if (at >= text.length()) {
                    throw error("unterminated string");
                }
                char c = text.charAt(at++);
                if (c == '"') {
                    return out.toString();
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                char e = text.charAt(at++);
                switch (e) {
                    case '"', '\\', '/' -> out.append(e);
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        out.append((char) Integer.parseInt(text.substring(at, at + 4), 16));
                        at += 4;
                    }
                    default -> throw error("bad escape \\" + e);
                }
            }
        }

        private Number number() {
            int start = at;
            while (at < text.length() && "+-0123456789.eE".indexOf(text.charAt(at)) >= 0) {
                at++;
            }
            String token = text.substring(start, at);
            if (token.isEmpty()) {
                throw error("unexpected character");
            }
            if (token.contains(".") || token.contains("e") || token.contains("E")) {
                return Double.parseDouble(token);
            }
            return Long.parseLong(token);
        }

        private Object literal(String word, Object value) {
            if (!text.startsWith(word, at)) {
                throw error("expected " + word);
            }
            at += word.length();
            return value;
        }

        private void skipSpace() {
            while (at < text.length() && Character.isWhitespace(text.charAt(at))) {
                at++;
            }
        }

        private char peek() {
            return at < text.length() ? text.charAt(at) : '\0';
        }

        private void expect(char c) {
            if (peek() != c) {
                throw error("expected '" + c + "'");
            }
            at++;
        }

        private IllegalStateException error(String message) {
            return new IllegalStateException("JSON: " + message + " at offset " + at);
        }
    }
}
