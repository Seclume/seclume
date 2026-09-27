package space.seclume.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * What an HTTP/2 client writes, with secrets written where the client wrote
 * their placeholders - in header values, never in DATA.
 *
 * <p>The frames are followed: the connection preface and every frame but
 * HEADERS and CONTINUATION go through as they are. A header block - a
 * HEADERS frame and its CONTINUATIONs - is decoded (HPACK, with a mirror of
 * the client's dynamic table, which the client keeps in step with its own
 * requests only) and encoded again for the server: every field a literal
 * <i>without indexing</i>, so the server's dynamic table stays empty and
 * nothing seclume sends can be referred to later; a field that carries a
 * secret <i>never indexed</i>, and built in native memory with the secret
 * where its placeholder was. Huffman-coded strings - which the gRPC OkHttp
 * transport does not write - are refused rather than guessed at.
 */
final class Http2Requests {

    /** Where the rewritten bytes go - seclume's TLS. */
    interface Sink {
        void write(ByteBuffer bytes) throws IOException;
    }

    private static final byte[] PREFIX =
            CredentialPlaceholders.PREFIX.getBytes(StandardCharsets.US_ASCII); // seclume-allow: the placeholder's prefix - no secret
    private static final int PREFACE = 24;
    private static final int HEADERS = 0x1;
    private static final int CONTINUATION = 0x9;
    private static final int END_STREAM = 0x1;
    private static final int END_HEADERS = 0x4;
    private static final int PADDED = 0x8;
    private static final int PRIORITY = 0x20;
    /** Every server takes frames of this size - the smallest SETTINGS_MAX_FRAME_SIZE there is. */
    private static final int FRAME = 16384;
    private static final int MAX_BLOCK = 1 << 20;

    private final Sink sink;
    private int preface = PREFACE;
    private final byte[] header = new byte[9];
    private int headerFill;
    private long passing;
    private int collecting = -1;
    private final ByteArrayOutputStream payload = new ByteArrayOutputStream();
    private final ByteArrayOutputStream block = new ByteArrayOutputStream();
    private int blockStream;
    private int blockFlags;
    private byte[] priority;
    private boolean inBlock;
    private final Table table = new Table();

    Http2Requests(Sink sink) {
        this.sink = sink;
    }

    void consume(byte[] source, int offset, int length) throws IOException {
        int at = offset;
        int end = offset + length;
        while (at < end) {
            if (preface > 0) {
                int n = Math.min(preface, end - at);
                sink.write(ByteBuffer.wrap(source, at, n));
                at += n;
                preface -= n;
            } else if (passing > 0) {
                int n = (int) Math.min(passing, end - at);
                sink.write(ByteBuffer.wrap(source, at, n));
                at += n;
                passing -= n;
            } else if (collecting > 0) {
                int n = Math.min(collecting, end - at);
                payload.write(source, at, n);
                at += n;
                collecting -= n;
                if (collecting == 0) {
                    headerPayload();
                }
            } else {
                header[headerFill++] = source[at++];
                if (headerFill == header.length) {
                    headerFill = 0;
                    frame();
                }
            }
        }
    }

    /** A frame header is complete. */
    private void frame() throws IOException {
        int length = (header[0] & 0xff) << 16 | (header[1] & 0xff) << 8 | header[2] & 0xff;
        int type = header[3] & 0xff;
        boolean headers = type == HEADERS || type == CONTINUATION;
        if (inBlock != (type == CONTINUATION)) {
            throw new IOException("the HTTP/2 client interleaved a frame of type " + type
                    + (inBlock ? " into a header block" : " without a header block to continue"));
        }
        if (!headers) {
            sink.write(ByteBuffer.wrap(header.clone()));
            passing = length;
            return;
        }
        payload.reset();
        collecting = length;
        if (length == 0) {
            headerPayload();
        }
    }

    /** The payload of a HEADERS or CONTINUATION frame is complete. */
    private void headerPayload() throws IOException {
        collecting = -1;
        int type = header[3] & 0xff;
        int flags = header[4] & 0xff;
        byte[] bytes = payload.toByteArray();
        payload.reset();
        int from = 0;
        int to = bytes.length;
        if (type == HEADERS) {
            blockStream = (header[5] & 0x7f) << 24 | (header[6] & 0xff) << 16
                    | (header[7] & 0xff) << 8 | header[8] & 0xff;
            blockFlags = flags;
            priority = null;
            if ((flags & PADDED) != 0) {
                if (to < 1) {
                    throw new IOException("the HTTP/2 client wrote a padded HEADERS frame "
                            + "without its pad length");
                }
                to -= bytes[0] & 0xff;
                from = 1;
            }
            if ((flags & PRIORITY) != 0) {
                if (to - from < 5) {
                    throw new IOException("the HTTP/2 client wrote a HEADERS frame shorter "
                            + "than its priority fields");
                }
                priority = java.util.Arrays.copyOfRange(bytes, from, from + 5);
                from += 5;
            }
            if (to < from) {
                throw new IOException("the HTTP/2 client padded a HEADERS frame beyond its end");
            }
        }
        block.write(bytes, from, to - from);
        if (block.size() > MAX_BLOCK) {
            throw new IOException("the HTTP/2 client wrote a header block of more than "
                    + MAX_BLOCK + " bytes");
        }
        inBlock = (flags & END_HEADERS) == 0;
        if (!inBlock) {
            byte[] encoded = block.toByteArray();
            block.reset();
            send(decode(encoded));
        }
    }

    // ---- HPACK, as the client wrote it -------------------------------------------------

    private record Field(byte[] name, byte[] value) {
    }

    private record Block(List<Integer> sizeUpdates, List<Field> fields) {
    }

    private Block decode(byte[] bytes) throws IOException {
        List<Integer> sizeUpdates = new ArrayList<>();
        List<Field> fields = new ArrayList<>();
        int[] at = {0};
        while (at[0] < bytes.length) {
            int b = bytes[at[0]] & 0xff;
            if ((b & 0x80) != 0) {
                fields.add(table.get(integer(bytes, at, 7)));
            } else if ((b & 0x40) != 0) {
                Field field = literal(bytes, at, 6);
                table.add(field);
                fields.add(field);
            } else if ((b & 0x20) != 0) {
                int size = integer(bytes, at, 5);
                table.resize(size);
                sizeUpdates.add(size);
            } else {
                fields.add(literal(bytes, at, 4));
            }
        }
        return new Block(sizeUpdates, fields);
    }

    private Field literal(byte[] bytes, int[] at, int prefix) throws IOException {
        int index = integer(bytes, at, prefix);
        byte[] name = index == 0 ? string(bytes, at) : table.get(index).name();
        return new Field(name, string(bytes, at));
    }

    private static byte[] string(byte[] bytes, int[] at) throws IOException {
        if (at[0] >= bytes.length) {
            throw new IOException("the HTTP/2 client's header block ends inside a field");
        }
        if ((bytes[at[0]] & 0x80) != 0) {
            throw new IOException("the HTTP/2 client Huffman-coded a header string; seclume "
                    + "rewrites plain ones only");
        }
        int length = integer(bytes, at, 7);
        if (length > bytes.length - at[0]) {
            throw new IOException("the HTTP/2 client's header string runs past its block");
        }
        byte[] string = java.util.Arrays.copyOfRange(bytes, at[0], at[0] + length);
        at[0] += length;
        return string;
    }

    private static int integer(byte[] bytes, int[] at, int prefix) throws IOException {
        int mask = (1 << prefix) - 1;
        int value = bytes[at[0]++] & mask;
        if (value < mask) {
            return value;
        }
        int shift = 0;
        while (true) {
            if (at[0] >= bytes.length || shift > 21) {
                throw new IOException("the HTTP/2 client wrote an HPACK integer that does not end");
            }
            int b = bytes[at[0]++] & 0xff;
            value += (b & 0x7f) << shift;
            shift += 7;
            if ((b & 0x80) == 0) {
                return value;
            }
        }
    }

    // ---- HPACK, as the server gets it ----------------------------------------------------

    private void send(Block decoded) throws IOException {
        List<SecretScope> secrets = new ArrayList<>();
        try {
            // the secrets, read once each, and how long the block is with them
            List<int[]> spans = new ArrayList<>();          // per field: placeholder from, to
            int length = 0;
            for (int update : decoded.sizeUpdates()) {
                length += integerLength(update, 5);
            }
            for (Field field : decoded.fields()) {
                int found = indexOf(field.value(), PREFIX, 0);
                int valueLength = field.value().length;
                if (found >= 0) {
                    int end = placeholderEnd(field.value(), found);
                    SecretScope secret = SecretScope.fromProvider(provider(field.value(), found,
                            end));
                    secrets.add(secret);
                    spans.add(new int[] {found, end});
                    valueLength += secret.length() - (end - found);
                } else {
                    spans.add(null);
                }
                int index = Table.staticName(field.name());
                length += index > 0 ? integerLength(index, 4)
                        : 1 + integerLength(field.name().length, 7) + field.name().length;
                length += integerLength(valueLength, 7) + valueLength;
            }
            int frames = Math.max(1, (length + FRAME - 1) / FRAME);
            int total = length + 9 * frames + (priority == null ? 0 : 5);
            if (!secrets.isEmpty()) {
                try (SecretScope out = SecretScope.allocate(total)) {
                    write(out.segment(), decoded, spans, secrets, length);
                    sink.write(out.segment().asSlice(0, total).asByteBuffer());
                }
            } else {
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment out = arena.allocate(total);
                    write(out, decoded, spans, secrets, length);
                    sink.write(out.asSlice(0, total).asByteBuffer());
                }
            }
        } finally {
            for (SecretScope secret : secrets) {
                secret.close();
            }
        }
    }

    /** The block, and around it the frames, into {@code out}. */
    private void write(MemorySegment out, Block decoded, List<int[]> spans,
                       List<SecretScope> secrets, int length) {
        // the block first, at the end of the segment; then framed in place from the front
        int frames = Math.max(1, (length + FRAME - 1) / FRAME);
        int start = 9 * frames + (priority == null ? 0 : 5);
        Writer w = new Writer(out, start);
        for (int update : decoded.sizeUpdates()) {
            w.integer(update, 5, 0x20);
        }
        int secret = 0;
        for (int i = 0; i < decoded.fields().size(); i++) {
            Field field = decoded.fields().get(i);
            int[] span = spans.get(i);
            int index = Table.staticName(field.name());
            int kind = span == null ? 0x00 : 0x10;          // without indexing, never indexed
            if (index > 0) {
                w.integer(index, 4, kind);
            } else {
                w.integer(0, 4, kind);
                w.integer(field.name().length, 7, 0);
                w.bytes(field.name(), 0, field.name().length);
            }
            if (span == null) {
                w.integer(field.value().length, 7, 0);
                w.bytes(field.value(), 0, field.value().length);
            } else {
                SecretScope scope = secrets.get(secret++);
                byte[] value = field.value();
                w.integer(value.length - (span[1] - span[0]) + scope.length(), 7, 0);
                w.bytes(value, 0, span[0]);
                MemorySegment.copy(scope.segment(), 0, out, w.at, scope.length());
                w.at += scope.length();
                w.bytes(value, span[1], value.length - span[1]);
            }
        }
        // frame it: headers go before each piece, the pieces move forward
        int to = 0;
        int from = start;
        for (int f = 0; f < frames; f++) {
            int piece = Math.min(FRAME, length - (from - start));
            boolean first = f == 0;
            boolean last = f == frames - 1;
            int extra = first && priority != null ? 5 : 0;
            int flags = (first ? blockFlags & END_STREAM : 0) | (last ? END_HEADERS : 0)
                    | (extra > 0 ? PRIORITY : 0);
            int frameLength = piece + extra;
            out.set(ValueLayout.JAVA_BYTE, to, (byte) (frameLength >>> 16));
            out.set(ValueLayout.JAVA_BYTE, to + 1, (byte) (frameLength >>> 8));
            out.set(ValueLayout.JAVA_BYTE, to + 2, (byte) frameLength);
            out.set(ValueLayout.JAVA_BYTE, to + 3, (byte) (first ? HEADERS : CONTINUATION));
            out.set(ValueLayout.JAVA_BYTE, to + 4, (byte) flags);
            out.set(ValueLayout.JAVA_BYTE, to + 5, (byte) (blockStream >>> 24));
            out.set(ValueLayout.JAVA_BYTE, to + 6, (byte) (blockStream >>> 16));
            out.set(ValueLayout.JAVA_BYTE, to + 7, (byte) (blockStream >>> 8));
            out.set(ValueLayout.JAVA_BYTE, to + 8, (byte) blockStream);
            to += 9;
            if (extra > 0) {
                MemorySegment.copy(priority, 0, out, ValueLayout.JAVA_BYTE, to, 5);
                to += 5;
            }
            // to <= from always: 9 (+5) bytes of header per piece were left free at the front
            MemorySegment.copy(out, from, out, to, piece);
            to += piece;
            from += piece;
        }
    }

    private static final class Writer {
        private final MemorySegment out;
        private int at;

        Writer(MemorySegment out, int at) {
            this.out = out;
            this.at = at;
        }

        void integer(int value, int prefix, int pattern) {
            int mask = (1 << prefix) - 1;
            if (value < mask) {
                out.set(ValueLayout.JAVA_BYTE, at++, (byte) (pattern | value));
                return;
            }
            out.set(ValueLayout.JAVA_BYTE, at++, (byte) (pattern | mask));
            int rest = value - mask;
            while (rest >= 0x80) {
                out.set(ValueLayout.JAVA_BYTE, at++, (byte) (rest & 0x7f | 0x80));
                rest >>>= 7;
            }
            out.set(ValueLayout.JAVA_BYTE, at++, (byte) rest);
        }

        void bytes(byte[] source, int from, int length) {
            MemorySegment.copy(source, from, out, ValueLayout.JAVA_BYTE, at, length);
            at += length;
        }
    }

    private static int integerLength(int value, int prefix) {
        int mask = (1 << prefix) - 1;
        if (value < mask) {
            return 1;
        }
        int length = 2;
        for (int rest = value - mask; rest >= 0x80; rest >>>= 7) {
            length++;
        }
        return length;
    }

    private static int placeholderEnd(byte[] bytes, int found) {
        int end = found + PREFIX.length;
        while (end < bytes.length && CredentialPlaceholders.placeholderChar(bytes[end])) {
            end++;
        }
        return end;
    }

    private static SecretProvider provider(byte[] bytes, int from, int to) throws IOException {
        // seclume-allow: the placeholder - no secret
        String placeholder = new String(bytes, from, to - from, StandardCharsets.US_ASCII);
        SecretProvider provider = CredentialPlaceholders.provider(placeholder);
        if (provider == null) {
            throw new IOException("a credential placeholder this process did not hand out");
        }
        return provider;
    }

    private static int indexOf(byte[] data, byte[] pattern, int from) {
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

    /** HPACK's static table and a mirror of the client's dynamic one. */
    private static final class Table {

        private static final String[][] STATIC = {
            {":authority", ""}, {":method", "GET"}, {":method", "POST"}, {":path", "/"},
            {":path", "/index.html"}, {":scheme", "http"}, {":scheme", "https"},
            {":status", "200"}, {":status", "204"}, {":status", "206"}, {":status", "304"},
            {":status", "400"}, {":status", "404"}, {":status", "500"}, {"accept-charset", ""},
            {"accept-encoding", "gzip, deflate"}, {"accept-language", ""}, {"accept-ranges", ""},
            {"accept", ""}, {"access-control-allow-origin", ""}, {"age", ""}, {"allow", ""},
            {"authorization", ""}, {"cache-control", ""}, {"content-disposition", ""},
            {"content-encoding", ""}, {"content-language", ""}, {"content-length", ""},
            {"content-location", ""}, {"content-range", ""}, {"content-type", ""},
            {"cookie", ""}, {"date", ""}, {"etag", ""}, {"expect", ""}, {"expires", ""},
            {"from", ""}, {"host", ""}, {"if-match", ""}, {"if-modified-since", ""},
            {"if-none-match", ""}, {"if-range", ""}, {"if-unmodified-since", ""},
            {"last-modified", ""}, {"link", ""}, {"location", ""}, {"max-forwards", ""},
            {"proxy-authenticate", ""}, {"proxy-authorization", ""}, {"range", ""},
            {"referer", ""}, {"refresh", ""}, {"retry-after", ""}, {"server", ""},
            {"set-cookie", ""}, {"strict-transport-security", ""}, {"transfer-encoding", ""},
            {"user-agent", ""}, {"vary", ""}, {"via", ""}, {"www-authenticate", ""},
        };

        private static final Field[] FIELDS = new Field[STATIC.length];

        static {
            for (int i = 0; i < STATIC.length; i++) {
                FIELDS[i] = new Field(ascii(STATIC[i][0]), ascii(STATIC[i][1]));
            }
        }

        private static byte[] ascii(String text) {
            return text.getBytes(StandardCharsets.US_ASCII); // seclume-allow: HPACK's static table - public
        }

        private final Deque<Field> dynamic = new ArrayDeque<>();
        private int size;
        private int max = 4096;

        Field get(int index) throws IOException {
            if (index >= 1 && index <= STATIC.length) {
                return FIELDS[index - 1];
            }
            int dynamicIndex = index - STATIC.length - 1;
            if (index < 1 || dynamicIndex >= dynamic.size()) {
                throw new IOException("the HTTP/2 client referred to HPACK index " + index
                        + ", which it never defined");
            }
            int i = 0;
            for (Field field : dynamic) {
                if (i++ == dynamicIndex) {
                    return field;
                }
            }
            throw new IllegalStateException("index " + index + " vanished");
        }

        void add(Field field) {
            int entry = field.name().length + field.value().length + 32;
            if (entry > max) {
                dynamic.clear();
                size = 0;
                return;
            }
            dynamic.addFirst(field);
            size += entry;
            evict();
        }

        void resize(int newMax) {
            max = newMax;
            evict();
        }

        private void evict() {
            while (size > max) {
                Field last = dynamic.removeLast();
                size -= last.name().length + last.value().length + 32;
            }
        }

        /** The static table's index of this name, or 0. */
        static int staticName(byte[] name) {
            for (int i = 0; i < STATIC.length; i++) {
                if (java.util.Arrays.equals(name, FIELDS[i].name())) {
                    return i + 1;
                }
            }
            return 0;
        }
    }
}
