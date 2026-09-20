package space.seclume.internal;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Enough JSON to find one value in a secret manager's answer, in place.
 *
 * <p>The answer contains a password. Handing it to Jackson, Gson or
 * {@code javax.json} means the whole document becomes a tree of
 * {@code String}s - the password among them - and no {@code String} can be
 * wiped. So the document is navigated where it landed, in native memory, and
 * only the one value asked for is copied out, into a segment the caller owns
 * and zeroes.
 *
 * <p>This is a <b>reader</b>, not a parser: it walks to a path and stops. It
 * does not build a model, does not keep positions it has passed, and refuses
 * anything it does not understand rather than guessing. What it does
 * understand is what RFC 8259 defines - objects, arrays, strings with their
 * escapes including {@code \\uXXXX}, numbers, and the three literals.
 *
 * <p>Why not search for {@code "password":} and take what follows: because
 * that also matches inside a string value, inside a key that merely ends in
 * the same letters, and inside a nested object that happens to have a field
 * of that name. A credential is not a good place for a heuristic.
 */
public final class JsonOff {

    private JsonOff() {
    }

    /** Thrown when the document is malformed or the path is not in it. */
    public static final class NotFound extends RuntimeException {

        private static final long serialVersionUID = 1L;

        public NotFound(String message) {
            super(message);
        }
    }

    /**
     * Copies the string at {@code path} into {@code out}, unescaped.
     *
     * @param path field names from the root, e.g. {@code "data", "data",
     *             "password"}
     * @return how many bytes were written
     */
    public static int string(MemorySegment json, int length, MemorySegment out,
            String... path) {
        Cursor cursor = new Cursor(json, length);
        cursor.walk(path);
        cursor.skipWhitespace();
        if (cursor.peek() != '"') {
            throw new NotFound("the value at " + String.join(".", path) + " is not a string");
        }
        return cursor.readString(out);
    }

    /**
     * The number at {@code path}, as a {@code long}.
     *
     * <p>For {@code lease_duration} and nothing else so far, which is why
     * fractions are refused rather than rounded: a TTL with a decimal point is
     * a sign of a different API than the one this was written for.
     */
    public static long number(MemorySegment json, int length, String... path) {
        Cursor cursor = new Cursor(json, length);
        cursor.walk(path);
        cursor.skipWhitespace();
        long value = 0;
        boolean negative = cursor.peek() == '-';
        if (negative) {
            cursor.next();
        }
        int digits = 0;
        while (cursor.hasMore() && cursor.peek() >= '0' && cursor.peek() <= '9') {
            value = value * 10 + (cursor.next() - '0');
            digits++;
        }
        if (digits == 0) {
            throw new NotFound("the value at " + String.join(".", path) + " is not a number");
        }
        if (cursor.hasMore() && (cursor.peek() == '.' || cursor.peek() == 'e'
                || cursor.peek() == 'E')) {
            throw new NotFound("the value at " + String.join(".", path)
                    + " is not a whole number");
        }
        return negative ? -value : value;
    }

    /** Whether the path exists at all - for an optional field. */
    public static boolean has(MemorySegment json, int length, String... path) {
        try {
            new Cursor(json, length).walk(path);
            return true;
        } catch (NotFound absent) {
            return false;
        }
    }

    /** A position in the document, and the few moves that are needed. */
    private static final class Cursor {

        private final MemorySegment data;
        private final int end;
        private int at;

        Cursor(MemorySegment data, int length) {
            this.data = data;
            this.end = length;
        }

        /** Descends through the named fields, leaving the cursor on the value. */
        void walk(String... path) {
            for (String field : path) {
                skipWhitespace();
                if (peek() != '{') {
                    throw new NotFound("expected an object while looking for '" + field + "'");
                }
                next();
                if (!findField(field)) {
                    throw new NotFound("the answer has no field '" + field + "'");
                }
            }
        }

        /** @return true with the cursor on the value of {@code field} */
        private boolean findField(String field) {
            while (true) {
                skipWhitespace();
                if (peek() == '}') {
                    return false;
                }
                if (peek() != '"') {
                    throw new NotFound("expected a field name");
                }
                boolean match = stringEquals(field);
                skipWhitespace();
                if (next() != ':') {
                    throw new NotFound("expected ':' after a field name");
                }
                if (match) {
                    return true;
                }
                skipValue();
                skipWhitespace();
                if (!hasMore()) {
                    return false;
                }
                if (peek() == ',') {
                    next();
                } else if (peek() == '}') {
                    return false;
                } else {
                    throw new NotFound("expected ',' or '}' in an object");
                }
            }
        }

        /**
         * Compares the string at the cursor with {@code expected} and consumes
         * it either way.
         *
         * <p>Field names are compared byte for byte without unescaping. A
         * secret manager that wrote {@code "pass\\u0077ord"} as a key would
         * not be matched - which is the safe direction: the field is reported
         * as missing rather than a different one being taken for it.
         */
        private boolean stringEquals(String expected) {
            next();                                   // the opening quote
            int i = 0;
            boolean match = true;
            while (hasMore()) {
                byte b = next();
                if (b == '"') {
                    return match && i == expected.length();
                }
                if (b == '\\') {
                    next();
                    match = false;
                    continue;
                }
                if (i >= expected.length() || (expected.charAt(i) & 0xff) != (b & 0xff)
                        || expected.charAt(i) > 0x7f) {
                    match = false;
                }
                i++;
            }
            throw new NotFound("a field name never ended");
        }

        /** Copies the string at the cursor into {@code out}, unescaped. */
        int readString(MemorySegment out) {
            next();                                   // the opening quote
            int written = 0;
            while (hasMore()) {
                byte b = next();
                if (b == '"') {
                    return written;
                }
                if (b != '\\') {
                    written = put(out, written, b);
                    continue;
                }
                byte escape = next();
                switch (escape) {
                    case '"', '\\', '/' -> written = put(out, written, escape);
                    case 'b' -> written = put(out, written, (byte) 0x08);
                    case 'f' -> written = put(out, written, (byte) 0x0c);
                    case 'n' -> written = put(out, written, (byte) '\n');
                    case 'r' -> written = put(out, written, (byte) '\r');
                    case 't' -> written = put(out, written, (byte) '\t');
                    case 'u' -> written = putUtf8(out, written, readHex4());
                    default -> throw new NotFound("unknown escape in a JSON string");
                }
            }
            throw new NotFound("a string value never ended");
        }

        private int readHex4() {
            int value = 0;
            for (int i = 0; i < 4; i++) {
                int digit = Character.digit((char) (next() & 0xff), 16);
                if (digit < 0) {
                    throw new NotFound("a \\u escape is not four hex digits");
                }
                value = value * 16 + digit;
            }
            return value;
        }

        /**
         * One code point as UTF-8.
         *
         * <p>Surrogate pairs are not joined: a password outside the basic
         * multilingual plane is not a thing that happens, and writing the
         * surrogates through unchanged would produce invalid UTF-8 silently.
         * Refusing says what happened.
         */
        private int putUtf8(MemorySegment out, int written, int code) {
            if (code >= 0xd800 && code <= 0xdfff) {
                throw new NotFound("a \\u escape outside the basic multilingual plane");
            }
            if (code < 0x80) {
                return put(out, written, (byte) code);
            }
            if (code < 0x800) {
                written = put(out, written, (byte) (0xc0 | (code >> 6)));
                return put(out, written, (byte) (0x80 | (code & 0x3f)));
            }
            written = put(out, written, (byte) (0xe0 | (code >> 12)));
            written = put(out, written, (byte) (0x80 | ((code >> 6) & 0x3f)));
            return put(out, written, (byte) (0x80 | (code & 0x3f)));
        }

        private static int put(MemorySegment out, int written, byte value) {
            if (written >= out.byteSize()) {
                throw new NotFound("the value is longer than the space provided for it");
            }
            out.set(ValueLayout.JAVA_BYTE, written, value);
            return written + 1;
        }

        /** Steps over any value, however nested, without looking inside it. */
        private void skipValue() {
            skipWhitespace();
            byte b = peek();
            if (b == '"') {
                stringEquals("");                     // consumes it; the answer is ignored
                return;
            }
            if (b == '{' || b == '[') {
                byte open = b;
                byte close = b == '{' ? (byte) '}' : (byte) ']';
                int depth = 0;
                while (hasMore()) {
                    byte c = peek();
                    if (c == '"') {
                        stringEquals("");
                        continue;
                    }
                    next();
                    if (c == open) {
                        depth++;
                    } else if (c == close && --depth == 0) {
                        return;
                    }
                }
                throw new NotFound("a nested value never ended");
            }
            while (hasMore() && peek() != ',' && peek() != '}' && peek() != ']') {
                next();
            }
        }

        void skipWhitespace() {
            while (hasMore()) {
                byte b = peek();
                if (b != ' ' && b != '\t' && b != '\n' && b != '\r') {
                    return;
                }
                at++;
            }
        }

        boolean hasMore() {
            return at < end;
        }

        byte peek() {
            if (at >= end) {
                throw new NotFound("the answer ended in the middle of a value");
            }
            return data.get(ValueLayout.JAVA_BYTE, at);
        }

        byte next() {
            byte b = peek();
            at++;
            return b;
        }
    }
}
