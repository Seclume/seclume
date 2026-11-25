package space.seclume.heapdump;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.List;

/**
 * Named secrets a redaction looks for <b>without putting them on the heap</b>:
 * an application redacting its own dump knows its secrets - seclume holds them
 * in native memory - and searching for one with a {@code byte[]} pattern would
 * leave a copy of it on the very heap the next dump is taken of.
 *
 * <p>So the patterns are {@link MemorySegment}s, built in native memory from
 * the secret as its provider wrote it, and the dump is searched in native
 * windows too. A secret that never left native memory is not in the dump at
 * all; what this finds is a copy that did leave - in a log line, a
 * configuration object, an exception message - and it goes like any other.
 */
public interface OffHeapSecrets {

    /** The secrets for one redaction; closing what comes back wipes them. */
    Opened open();

    /** Secrets opened for one redaction. */
    interface Opened extends AutoCloseable {

        List<Needle> needles();

        /** Wipes and releases every pattern. */
        @Override
        void close();
    }

    /** One secret as the patterns it can lie in, each in native memory. */
    record Needle(String label, List<Pattern> patterns) {

        public Needle {
            patterns = List.copyOf(patterns);
        }

        int longest() {
            return patterns.stream().mapToInt(p -> (int) p.bytes().byteSize()).max().orElse(1);
        }
    }

    /** One encoding of a secret, and how its occurrences are overwritten. */
    record Pattern(String encoding, MemorySegment bytes, Redactor.Fill fill) {
    }

    /**
     * A secret that is text, given as UTF-8 in native memory: itself, as
     * UTF-16 in both byte orders - decoded here, in native memory - and as
     * Base64; and as Latin-1 where it is that but not ASCII, the way a
     * compact {@code String} holds it. Every pattern is allocated by {@code allocator}, which is the
     * caller's to wipe. A secret that is not UTF-8 is looked for as bytes.
     */
    static Needle text(String label, MemorySegment utf8, SegmentAllocator allocator) {
        if (utf8.byteSize() == 0) {
            throw new IllegalArgumentException("an empty secret matches everywhere");
        }
        List<Pattern> patterns = new ArrayList<>();
        patterns.add(new Pattern("UTF-8", utf8, Redactor.Fill.ASCII));
        long units = Native.utf16Units(utf8);
        if (units < 0) {
            return bytes(label, utf8, allocator);
        }
        MemorySegment be = allocator.allocate(units * 2);
        MemorySegment le = allocator.allocate(units * 2);
        Native.utf16(utf8, be, true);
        Native.utf16(utf8, le, false);
        patterns.add(new Pattern("UTF-16BE", be, Redactor.Fill.UTF16_BE));
        patterns.add(new Pattern("UTF-16LE", le, Redactor.Fill.UTF16_LE));
        patterns.add(new Pattern("Base64", Native.base64(utf8, allocator), Redactor.Fill.ASCII));
        MemorySegment latin1 = Native.latin1(utf8, units, allocator);
        if (latin1 != null) {
            patterns.add(new Pattern("ISO-8859-1", latin1, Redactor.Fill.ASCII));
        }
        embedded(utf8, allocator, patterns);
        for (boolean form : new boolean[] {false, true}) {
            for (boolean lower : new boolean[] {false, true}) {
                add(patterns, "percent-encoded", Native.percent(utf8, form, lower, allocator));
            }
        }
        add(patterns, "JSON-escaped", Native.json(utf8, allocator));
        return new Needle(label, patterns);
    }

    /** A secret that is bytes - a key: itself, zeroed where found, and as Base64. */
    static Needle bytes(String label, MemorySegment secret, SegmentAllocator allocator) {
        if (secret.byteSize() == 0) {
            throw new IllegalArgumentException("an empty secret matches everywhere");
        }
        List<Pattern> patterns = new ArrayList<>(List.of(new Pattern("bytes", secret, Redactor.Fill.ZERO),
                new Pattern("Base64", Native.base64(secret, allocator), Redactor.Fill.ASCII)));
        embedded(secret, allocator, patterns);
        return new Needle(label, patterns);
    }

    /**
     * Its Base64 inside a longer Base64 text - {@code Basic base64(user:password)}
     * - at each of the three places a byte can start, standard and URL-safe: the
     * stretch made of the secret's bytes alone, when it is long enough not to be
     * found anywhere by chance (see {@link Encodings}).
     */
    private static void embedded(MemorySegment data, SegmentAllocator allocator, List<Pattern> patterns) {
        for (int offset = 0; offset < 3; offset++) {
            for (boolean urlSafe : new boolean[] {false, true}) {
                add(patterns, "Base64 inside", Native.base64Inside(data, offset, urlSafe, allocator));
            }
        }
    }

    /** {@code bytes} as one more pattern, filled as ASCII - unless null or one there is already. */
    private static void add(List<Pattern> patterns, String encoding, MemorySegment bytes) {
        if (bytes == null) {
            return;
        }
        for (Pattern known : patterns) {
            if (known.bytes().byteSize() == bytes.byteSize() && known.bytes().mismatch(bytes) < 0) {
                return;
            }
        }
        patterns.add(new Pattern(encoding, bytes, Redactor.Fill.ASCII));
    }

    /** Encodings computed in native memory, byte by byte, with nothing on the heap. */
    final class Native {

        private static final byte[] ALPHABET =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" // seclume-allow: the Base64 alphabet, no secret
                        .getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        private Native() {
        }

        /** How many UTF-16 code units {@code utf8} decodes to, or -1 if it is not UTF-8. */
        static long utf16Units(MemorySegment utf8) {
            long units = 0;
            long i = 0;
            long n = utf8.byteSize();
            while (i < n) {
                int b = utf8.get(ValueLayout.JAVA_BYTE, i) & 0xff;
                int length = b < 0x80 ? 1 : (b & 0xe0) == 0xc0 ? 2 : (b & 0xf0) == 0xe0 ? 3
                        : (b & 0xf8) == 0xf0 ? 4 : -1;
                if (length < 0 || i + length > n) {
                    return -1;
                }
                for (int k = 1; k < length; k++) {
                    if ((utf8.get(ValueLayout.JAVA_BYTE, i + k) & 0xc0) != 0x80) {
                        return -1;
                    }
                }
                units += length == 4 ? 2 : 1;
                i += length;
            }
            return units;
        }

        /** Decodes {@code utf8} (valid, see {@link #utf16Units}) into {@code out} as UTF-16. */
        static void utf16(MemorySegment utf8, MemorySegment out, boolean bigEndian) {
            long i = 0;
            long at = 0;
            long n = utf8.byteSize();
            while (i < n) {
                int b = utf8.get(ValueLayout.JAVA_BYTE, i) & 0xff;
                int code;
                int length;
                if (b < 0x80) {
                    code = b;
                    length = 1;
                } else if ((b & 0xe0) == 0xc0) {
                    code = b & 0x1f;
                    length = 2;
                } else if ((b & 0xf0) == 0xe0) {
                    code = b & 0x0f;
                    length = 3;
                } else {
                    code = b & 0x07;
                    length = 4;
                }
                for (int k = 1; k < length; k++) {
                    code = (code << 6) | (utf8.get(ValueLayout.JAVA_BYTE, i + k) & 0x3f);
                }
                i += length;
                if (code >= 0x10000) {
                    int v = code - 0x10000;
                    at = unit(out, at, 0xd800 | (v >>> 10), bigEndian);
                    at = unit(out, at, 0xdc00 | (v & 0x3ff), bigEndian);
                } else {
                    at = unit(out, at, code, bigEndian);
                }
            }
        }

        /**
         * {@code utf8} (valid, {@code units} long) as Latin-1, one byte per
         * character, or null where a character is past U+00FF or none is past
         * U+007F (then it is the UTF-8 already).
         */
        static MemorySegment latin1(MemorySegment utf8, long units, SegmentAllocator allocator) {
            MemorySegment utf16 = allocator.allocate(units * 2);
            utf16(utf8, utf16, true);
            boolean wide = false;
            for (long i = 0; i < units; i++) {
                int unit = ((utf16.get(ValueLayout.JAVA_BYTE, 2 * i) & 0xff) << 8)
                        | (utf16.get(ValueLayout.JAVA_BYTE, 2 * i + 1) & 0xff);
                if (unit > 0xff) {
                    return null;
                }
                wide |= unit > 0x7f;
            }
            if (!wide) {
                return null;
            }
            MemorySegment out = allocator.allocate(units);
            for (long i = 0; i < units; i++) {
                out.set(ValueLayout.JAVA_BYTE, i, utf16.get(ValueLayout.JAVA_BYTE, 2 * i + 1));
            }
            return out;
        }

        private static long unit(MemorySegment out, long at, int unit, boolean bigEndian) {
            out.set(ValueLayout.JAVA_BYTE, at, (byte) (bigEndian ? unit >>> 8 : unit));
            out.set(ValueLayout.JAVA_BYTE, at + 1, (byte) (bigEndian ? unit : unit >>> 8));
            return at + 2;
        }

        /**
         * The Base64 of {@code data} where it starts {@code offset} bytes into a
         * group: the characters that depend on its bytes alone, or null when
         * there are fewer than {@link Encodings}'s eight.
         */
        static MemorySegment base64Inside(MemorySegment data, int offset, boolean urlSafe,
                SegmentAllocator allocator) {
            long n = data.byteSize();
            long from = (offset + 2) / 3 * 4;
            long to = (offset + n) / 3 * 4;
            if (to - from < 8) {
                return null;
            }
            MemorySegment shifted = allocator.allocate(offset + n);
            MemorySegment.copy(data, 0, shifted, offset, n);
            MemorySegment whole = base64(shifted, allocator);
            MemorySegment middle = allocator.allocate(to - from);
            MemorySegment.copy(whole, from, middle, 0, to - from);
            if (urlSafe) {
                for (long i = 0; i < middle.byteSize(); i++) {
                    byte b = middle.get(ValueLayout.JAVA_BYTE, i);
                    middle.set(ValueLayout.JAVA_BYTE, i, b == '+' ? (byte) '-' : b == '/' ? (byte) '_' : b);
                }
            }
            shifted.fill((byte) 0);
            whole.fill((byte) 0);
            return middle;
        }

        /** RFC 3986's unreserved kept, or - {@code form} - {@code URLEncoder}'s way; null when it is the text itself. */
        static MemorySegment percent(MemorySegment utf8, boolean form, boolean lower,
                SegmentAllocator allocator) {
            long n = utf8.byteSize();
            MemorySegment out = allocator.allocate(n * 3);
            long at = 0;
            boolean changed = false;
            for (long i = 0; i < n; i++) {
                int b = utf8.get(ValueLayout.JAVA_BYTE, i) & 0xff;
                boolean kept = (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
                        || b == '-' || b == '.' || b == '_' || (form ? b == '*' : b == '~');
                if (kept) {
                    out.set(ValueLayout.JAVA_BYTE, at++, (byte) b);
                } else if (form && b == ' ') {
                    out.set(ValueLayout.JAVA_BYTE, at++, (byte) '+');
                    changed = true;
                } else {
                    out.set(ValueLayout.JAVA_BYTE, at++, (byte) '%');
                    out.set(ValueLayout.JAVA_BYTE, at++, hex(b >>> 4, lower));
                    out.set(ValueLayout.JAVA_BYTE, at++, hex(b & 0xf, lower));
                    changed = true;
                }
            }
            if (!changed || (lower && !hasLetterDigit(out, at))) {
                out.fill((byte) 0);
                return null;
            }
            return out.asSlice(0, at);
        }

        private static byte hex(int nibble, boolean lower) {
            return (byte) (nibble < 10 ? '0' + nibble : (lower ? 'a' : 'A') + nibble - 10);
        }

        /** Whether a %XX in {@code out} has a letter among its digits - else lower case changes nothing. */
        private static boolean hasLetterDigit(MemorySegment out, long length) {
            for (long i = 0; i + 2 < length; i++) {
                if (out.get(ValueLayout.JAVA_BYTE, i) == '%') {
                    for (int k = 1; k <= 2; k++) {
                        byte c = out.get(ValueLayout.JAVA_BYTE, i + k);
                        if (c >= 'a' && c <= 'f') {
                            return true;
                        }
                    }
                    i += 2;
                }
            }
            return false;
        }

        /** The text as a JSON string's content - " \ and line breaks escaped; null where it has none. */
        static MemorySegment json(MemorySegment utf8, SegmentAllocator allocator) {
            long n = utf8.byteSize();
            MemorySegment out = allocator.allocate(n * 2);
            long at = 0;
            boolean changed = false;
            for (long i = 0; i < n; i++) {
                byte b = utf8.get(ValueLayout.JAVA_BYTE, i);
                byte escape = switch (b) {
                    case '"' -> (byte) '"';
                    case '\\' -> (byte) '\\';
                    case '\n' -> (byte) 'n';
                    case '\r' -> (byte) 'r';
                    case '\t' -> (byte) 't';
                    default -> 0;
                };
                if (escape != 0) {
                    out.set(ValueLayout.JAVA_BYTE, at++, (byte) '\\');
                    out.set(ValueLayout.JAVA_BYTE, at++, escape);
                    changed = true;
                } else {
                    out.set(ValueLayout.JAVA_BYTE, at++, b);
                }
            }
            if (!changed) {
                out.fill((byte) 0);
                return null;
            }
            return out.asSlice(0, at);
        }

        /** {@code data} as Base64 with padding, written by {@code allocator}. */
        static MemorySegment base64(MemorySegment data, SegmentAllocator allocator) {
            long n = data.byteSize();
            MemorySegment out = allocator.allocate(((n + 2) / 3) * 4);
            long at = 0;
            for (long i = 0; i < n; i += 3) {
                int b0 = data.get(ValueLayout.JAVA_BYTE, i) & 0xff;
                int b1 = i + 1 < n ? data.get(ValueLayout.JAVA_BYTE, i + 1) & 0xff : 0;
                int b2 = i + 2 < n ? data.get(ValueLayout.JAVA_BYTE, i + 2) & 0xff : 0;
                out.set(ValueLayout.JAVA_BYTE, at++, ALPHABET[b0 >>> 2]);
                out.set(ValueLayout.JAVA_BYTE, at++, ALPHABET[((b0 & 3) << 4) | (b1 >>> 4)]);
                out.set(ValueLayout.JAVA_BYTE, at++, i + 1 < n
                        ? ALPHABET[((b1 & 0xf) << 2) | (b2 >>> 6)] : (byte) '=');
                out.set(ValueLayout.JAVA_BYTE, at++, i + 2 < n ? ALPHABET[b2 & 0x3f]
                        : (byte) '=');
            }
            return out;
        }
    }
}
