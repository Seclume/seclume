package space.seclume.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import space.seclume.internal.Base64Off;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * The HTTP/1.1 framing of what a client writes - request head, then a body
 * of {@code Content-Length} bytes or in chunks - followed byte by byte, and
 * the rule for what is written into a head: one place for both the socket
 * ({@link CredentialSocket}) and the engine ({@link HttpCredentialRewriter}),
 * so that they cannot come to disagree about where a secret may go.
 *
 * <p>In each <b>head</b>, in its header lines - never in the request line,
 * whose target is the application's data:
 *
 * <ul>
 *   <li>the secret where a placeholder stands - a bearer token, an API key
 *       header;
 *   <li>{@code Basic base64(user:secret)} where the client wrote
 *       {@code Basic base64(user:placeholder)} - decoded and encoded again in
 *       native memory.
 * </ul>
 *
 * <p>Bodies go through untouched, whatever they contain: a document that
 * holds a placeholder is indexed with the placeholder, not the secret.
 */
final class HttpFraming {

    static final byte[] PREFIX =
            CredentialPlaceholders.PREFIX.getBytes(StandardCharsets.US_ASCII); // seclume-allow: the placeholder's prefix - no secret

    /** A head this long is not one a client of a REST API writes; refused rather than held. */
    static final int MAX_HEAD = 64 * 1024;

    private enum State { HEAD, BODY, CHUNK_SIZE, CHUNK_DATA, CHUNK_END, TRAILER }

    private State state = State.HEAD;
    private final ByteArrayOutputStream head = new ByteArrayOutputStream();
    private final ByteArrayOutputStream line = new ByteArrayOutputStream();
    private long remaining;

    /** Whether the next byte belongs to a request head. */
    boolean inHead() {
        return state == State.HEAD;
    }

    /** How many bytes of the head are held so far. */
    int held() {
        return head.size();
    }

    /**
     * Takes one byte of a head. @return the whole head once its blank line
     * has come - the framing then follows its body - else null
     */
    byte[] headByte(byte b) throws IOException {
        head.write(b);
        if (head.size() > MAX_HEAD) {
            throw new IOException("a request head of more than " + MAX_HEAD + " bytes");
        }
        if (!endsWithBlankLine()) {
            return null;
        }
        byte[] bytes = head.toByteArray();
        head.reset();
        String text = new String(bytes, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT); // seclume-allow: a request head with placeholders - no secret
        frame(text);
        return bytes;
    }

    /**
     * Where the body of the request whose head is {@code text} ends - as the
     * server will see it, RFC 9112 section 6. A body the framing took for a
     * head would have secrets written into it; so whatever the server could
     * read another way than this is refused rather than guessed: a folded
     * line, a space before a colon, a coding after {@code chunked}, two
     * lengths that differ, a length that is not digits.
     *
     * <p>Not only {@code Transfer-Encoding: chunked} with one space: a client
     * may write {@code transfer-encoding:chunked}, a tab, or
     * {@code gzip, chunked}. Each was taken for no body, and the chunks that
     * followed - the body - for the next head.
     */
    private void frame(String text) throws IOException {
        String[] lines = text.split("\r\n", -1);
        StringBuilder codings = new StringBuilder();
        String length = null;
        for (int i = 1; i < lines.length && !lines[i].isEmpty(); i++) {
            String line = lines[i];
            if (line.charAt(0) == ' ' || line.charAt(0) == '\t') {
                throw new IOException("the HTTP client folded a header line - the framing "
                        + "of the request cannot be followed");
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String name = line.substring(0, colon);
            if (name.endsWith(" ") || name.endsWith("\t")) {
                throw new IOException("the HTTP client wrote a space before a header's colon");
            }
            String value = line.substring(colon + 1).strip();
            if (name.equals("transfer-encoding")) {
                codings.append(codings.isEmpty() ? "" : ",").append(value);
            } else if (name.equals("content-length")) {
                if (!value.matches("[0-9]{1,18}")) {
                    throw new IOException("the HTTP client wrote a length that is not a number: '"
                            + value + "'");
                }
                if (length != null && !length.equals(value)) {
                    throw new IOException("the HTTP client wrote two lengths, " + length
                            + " and " + value);
                }
                length = value;
            }
        }
        if (!codings.isEmpty()) {
            List<String> each = new ArrayList<>();
            for (String coding : codings.toString().split(",")) {
                if (!coding.isBlank()) {
                    each.add(coding.strip());
                }
            }
            if (each.isEmpty() || !each.get(each.size() - 1).equals("chunked")
                    || each.indexOf("chunked") != each.size() - 1) {
                throw new IOException("the HTTP client wrote Transfer-Encoding: " + codings
                        + " - a request body whose last coding is not chunked, once, has no end "
                        + "a server can find");
            }
            state = State.CHUNK_SIZE;           // over any Content-Length (RFC 9112, 6.3)
            return;
        }
        long bytes = length == null ? 0 : Long.parseLong(length);
        if (bytes > 0) {
            state = State.BODY;
            remaining = bytes;
        } else {
            state = State.HEAD;
        }
    }

    /**
     * Outside a head: how many of the bytes from {@code source}'s position -
     * not moved - go through as they are, at most {@code most}; the framing
     * moved past them. At least one.
     */
    int passThrough(java.nio.ByteBuffer source, int most) throws IOException {
        return switch (state) {
            case BODY, CHUNK_DATA -> {
                int n = (int) Math.min(remaining, Math.min(most, source.remaining()));
                remaining -= n;
                if (remaining == 0) {
                    state = state == State.BODY ? State.HEAD : State.CHUNK_END;
                    remaining = 2;
                }
                yield n;
            }
            case CHUNK_END -> {
                if (--remaining == 0) {
                    state = State.CHUNK_SIZE;
                }
                yield 1;
            }
            case CHUNK_SIZE, TRAILER -> {
                byte b = source.get(source.position());
                line.write(b);
                if (b == '\n') {
                    String text = line.toString(StandardCharsets.US_ASCII).trim();
                    line.reset();
                    if (state == State.TRAILER) {
                        if (text.isEmpty()) {
                            state = State.HEAD;
                        }
                    } else {
                        int semicolon = text.indexOf(';');
                        long size = number(semicolon < 0 ? text
                                : text.substring(0, semicolon).trim(), 16);
                        if (size == 0) {
                            state = State.TRAILER;
                        } else {
                            state = State.CHUNK_DATA;
                            remaining = size;
                        }
                    }
                }
                yield 1;
            }
            case HEAD -> throw new IllegalStateException("a head is taken byte by byte");
        };
    }

    private boolean endsWithBlankLine() {
        int size = head.size();
        if (size < 4) {
            return false;
        }
        byte[] bytes = head.toByteArray();
        return bytes[size - 4] == '\r' && bytes[size - 3] == '\n' && bytes[size - 2] == '\r'
                && bytes[size - 1] == '\n';
    }

    // ---- what goes into a head --------------------------------------------------------

    /** Whether {@code head} has anything to write a secret into. */
    static boolean carriesPlaceholder(byte[] head) {
        String text = new String(head, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT); // seclume-allow: a request head with placeholders - no secret
        return indexOf(head, PREFIX, 0) >= 0 || text.contains(": basic ");
    }

    /**
     * The head with the secrets written where their placeholders are, in
     * native memory; its length is the scope's.
     */
    static SecretScope rewrite(byte[] bytes, String server) throws IOException {
        SecretScope out = SecretScope.allocateShared(bytes.length * 2 + 64 * 1024);
        try {
            MemorySegment w = out.segment();
            // The request line as it is: its target is where an application
            // puts what its users typed - a search, a path - and the
            // placeholder is no secret (the client holds it on the heap).
            // Written there, the secret would go to the server's access log
            // and back in whatever echoes the request. Only header lines carry
            // credentials.
            int line = 0;
            while (line < bytes.length && bytes[line] != '\n') {
                line++;
            }
            line = Math.min(line + 1, bytes.length);
            MemorySegment.copy(bytes, 0, w, ValueLayout.JAVA_BYTE, 0, line);
            int at = line;
            while (line < bytes.length) {
                int end = line;
                while (end < bytes.length && bytes[end] != '\n') {
                    end++;
                }
                end = Math.min(end + 1, bytes.length);
                at = rewriteLine(bytes, line, end, w, at, server);
                line = end;
            }
            out.length(at);
            return out;
        } catch (IOException | RuntimeException e) {
            out.close();
            throw e;
        }
    }

    /** One header line, secrets written in. @return where the next line goes */
    private static int rewriteLine(byte[] bytes, int from, int to, MemorySegment w, int at,
            String server) throws IOException {
        int basic = basicValue(bytes, from, to);
        if (basic >= 0) {
            int valueEnd = to;
            while (valueEnd > basic && (bytes[valueEnd - 1] == '\n' || bytes[valueEnd - 1] == '\r'
                    || bytes[valueEnd - 1] == ' ')) {
                valueEnd--;
            }
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment encoded = arena.allocate(Math.max(1, valueEnd - basic));
                MemorySegment.copy(bytes, basic, encoded, ValueLayout.JAVA_BYTE, 0,
                        valueEnd - basic);
                MemorySegment decoded = arena.allocate(
                        Base64Off.decodedUpperBound(valueEnd - basic) + 1);
                int size = Base64Off.decode(encoded, 0, valueEnd - basic, decoded, 0);
                byte[] plain = decoded.asSlice(0, size).toArray(ValueLayout.JAVA_BYTE); // seclume-allow: user:placeholder - no secret
                int found = indexOf(plain, PREFIX, 0);
                int placeholderEnd = found < 0 ? -1 : placeholderEnd(plain, found);
                SecretProvider provider = found < 0 ? null
                        : provider(plain, found, placeholderEnd, server);
                if (provider != null) {
                    try (SecretScope secret = SecretScope.fromProvider(provider);
                         SecretScope credentials = SecretScope.allocate(
                                 found + secret.length() + plain.length - placeholderEnd);
                         SecretScope base64 = SecretScope.allocate(Base64Off.encodedLength(
                                 found + secret.length() + plain.length - placeholderEnd))) {
                        MemorySegment c = credentials.segment();
                        MemorySegment.copy(plain, 0, c, ValueLayout.JAVA_BYTE, 0, found);
                        MemorySegment.copy(secret.segment(), 0, c, found, secret.length());
                        MemorySegment.copy(plain, placeholderEnd, c, ValueLayout.JAVA_BYTE,
                                found + secret.length(), plain.length - placeholderEnd);
                        int total = found + secret.length() + plain.length - placeholderEnd;
                        int written = Base64Off.encode(c, 0, total, base64.segment(), 0);
                        MemorySegment.copy(bytes, from, w, ValueLayout.JAVA_BYTE, at,
                                basic - from);
                        at += basic - from;
                        MemorySegment.copy(base64.segment(), 0, w, at, written);
                        at += written;
                        MemorySegment.copy(bytes, valueEnd, w, ValueLayout.JAVA_BYTE, at,
                                to - valueEnd);
                        return at + to - valueEnd;
                    }
                }
            }
        }
        int cursor = from;
        while (true) {
            int found = indexOf(bytes, PREFIX, cursor);
            if (found < 0 || found >= to) {
                MemorySegment.copy(bytes, cursor, w, ValueLayout.JAVA_BYTE, at, to - cursor);
                return at + to - cursor;
            }
            MemorySegment.copy(bytes, cursor, w, ValueLayout.JAVA_BYTE, at, found - cursor);
            at += found - cursor;
            int placeholderEnd = placeholderEnd(bytes, found);
            SecretProvider provider = provider(bytes, found, placeholderEnd, server);
            if (provider == null) {
                // Not this server's secret: the placeholder goes as it is.
                MemorySegment.copy(bytes, found, w, ValueLayout.JAVA_BYTE, at,
                        placeholderEnd - found);
                at += placeholderEnd - found;
            } else {
                try (SecretScope secret = SecretScope.fromProvider(provider)) {
                    MemorySegment.copy(secret.segment(), 0, w, at, secret.length());
                    at += secret.length();
                }
            }
            cursor = placeholderEnd;
        }
    }

    /** Where the base64 of a {@code Basic} credential starts in this line, or -1. */
    private static int basicValue(byte[] bytes, int from, int to) {
        int colon = -1;
        for (int i = from; i < to; i++) {
            if (bytes[i] == ':') {
                colon = i;
                break;
            }
        }
        if (colon < 0) {
            return -1;
        }
        String name = new String(bytes, from, colon - from, StandardCharsets.ISO_8859_1) // seclume-allow: a header's name
                .trim().toLowerCase(Locale.ROOT);
        if (!name.equals("authorization") && !name.equals("proxy-authorization")) {
            return -1;
        }
        int at = colon + 1;
        while (at < to && bytes[at] == ' ') {
            at++;
        }
        byte[] basic = {'b', 'a', 's', 'i', 'c', ' '};
        if (to - at < basic.length) {
            return -1;
        }
        for (int i = 0; i < basic.length; i++) {
            if (Character.toLowerCase((char) bytes[at + i]) != basic[i]) {
                return -1;
            }
        }
        return at + basic.length;
    }

    private static int placeholderEnd(byte[] bytes, int found) {
        int end = found + PREFIX.length;
        while (end < bytes.length && CredentialPlaceholders.placeholderChar(bytes[end])) {
            end++;
        }
        return end;
    }

    /** The provider, or null where this placeholder's secret does not go to {@code server}. */
    private static SecretProvider provider(byte[] bytes, int from, int to, String server)
            throws IOException {
        // seclume-allow: the placeholder - no secret
        String placeholder = new String(bytes, from, to - from, StandardCharsets.US_ASCII);
        return CredentialPlaceholders.provider(placeholder, server);
    }

    /** A length the client wrote - not one, and the framing cannot be followed. */
    private static long number(String text, int radix) throws IOException {
        // Digits only: Long.parseLong takes a sign too, and "+5" is no chunk size.
        if (!text.matches(radix == 16 ? "[0-9a-fA-F]{1,15}" : "[0-9]{1,18}")) {
            throw new IOException("the HTTP client wrote a length that is not a number: '"
                    + text + "'");
        }
        try {
            return Long.parseLong(text, radix);
        } catch (NumberFormatException e) {
            throw new IOException("the HTTP client wrote a length that is not a number: '"
                    + text + "'", e);
        }
    }

    static int indexOf(byte[] data, byte[] pattern, int from) {
        outer:
        for (int i = from; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
