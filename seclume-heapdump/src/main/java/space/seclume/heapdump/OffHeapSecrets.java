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
     * Base64. Every pattern is allocated by {@code allocator}, which is the
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
        return new Needle(label, patterns);
    }

    /** A secret that is bytes - a key: itself, zeroed where found, and as Base64. */
    static Needle bytes(String label, MemorySegment secret, SegmentAllocator allocator) {
        if (secret.byteSize() == 0) {
            throw new IllegalArgumentException("an empty secret matches everywhere");
        }
        return new Needle(label, List.of(new Pattern("bytes", secret, Redactor.Fill.ZERO),
                new Pattern("Base64", Native.base64(secret, allocator), Redactor.Fill.ASCII)));
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

        private static long unit(MemorySegment out, long at, int unit, boolean bigEndian) {
            out.set(ValueLayout.JAVA_BYTE, at, (byte) (bigEndian ? unit >>> 8 : unit));
            out.set(ValueLayout.JAVA_BYTE, at + 1, (byte) (bigEndian ? unit : unit >>> 8));
            return at + 2;
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
