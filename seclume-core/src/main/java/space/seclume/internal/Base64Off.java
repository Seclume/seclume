package space.seclume.internal;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Base64 between two off-heap segments.
 *
 * <p>{@link java.util.Base64} is ruled out: its decoder takes a {@code String}
 * or a {@code byte[]} and returns a {@code byte[]}. With SCRAM the client proof
 * goes through this encoding, with MySQL the PEM block of the server key -
 * intermediate values one has to be able to zero.
 *
 * <p>Only the standard alphabet with padding (RFC 4648, section 4); that is
 * what the database protocols use. Line breaks in the input are skipped while
 * decoding, so PEM fits in without preprocessing.
 */
public final class Base64Off {

    private static final byte[] ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    .getBytes(java.nio.charset.StandardCharsets.US_ASCII); // seclume-allow: a public constant alphabet, no secret

    /** Reverse table; -1 means "not a Base64 character". */
    private static final int[] VALUES = new int[256];

    static {
        java.util.Arrays.fill(VALUES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            VALUES[ALPHABET[i] & 0xff] = i;
        }
    }

    private Base64Off() {
    }

    /** How many bytes {@link #encode} writes. */
    public static int encodedLength(int rawLength) {
        return ((rawLength + 2) / 3) * 4;
    }

    /** Upper bound for {@link #decode}; the method returns the exact length. */
    public static int decodedUpperBound(int encodedLength) {
        return (encodedLength / 4 + 1) * 3;
    }

    /**
     * Encodes {@code length} bytes starting at {@code offset}.
     *
     * @return the number of characters written
     */
    public static int encode(MemorySegment source, long offset, int length,
                             MemorySegment target, long targetOffset) {
        long out = targetOffset;
        int i = 0;
        while (i + 2 < length) {
            int block = ((byteAt(source, offset + i) & 0xff) << 16)
                    | ((byteAt(source, offset + i + 1) & 0xff) << 8)
                    | (byteAt(source, offset + i + 2) & 0xff);
            setByte(target, out++, ALPHABET[(block >>> 18) & 0x3f]);
            setByte(target, out++, ALPHABET[(block >>> 12) & 0x3f]);
            setByte(target, out++, ALPHABET[(block >>> 6) & 0x3f]);
            setByte(target, out++, ALPHABET[block & 0x3f]);
            i += 3;
        }
        int rest = length - i;
        if (rest == 1) {
            int block = (byteAt(source, offset + i) & 0xff) << 16;
            setByte(target, out++, ALPHABET[(block >>> 18) & 0x3f]);
            setByte(target, out++, ALPHABET[(block >>> 12) & 0x3f]);
            setByte(target, out++, (byte) '=');
            setByte(target, out++, (byte) '=');
        } else if (rest == 2) {
            int block = ((byteAt(source, offset + i) & 0xff) << 16)
                    | ((byteAt(source, offset + i + 1) & 0xff) << 8);
            setByte(target, out++, ALPHABET[(block >>> 18) & 0x3f]);
            setByte(target, out++, ALPHABET[(block >>> 12) & 0x3f]);
            setByte(target, out++, ALPHABET[(block >>> 6) & 0x3f]);
            setByte(target, out++, (byte) '=');
        }
        return (int) (out - targetOffset);
    }

    /**
     * Decodes {@code length} characters starting at {@code offset}. Whitespace
     * and line breaks are skipped.
     *
     * @return the number of bytes written
     */
    public static int decode(MemorySegment source, long offset, int length,
                             MemorySegment target, long targetOffset) {
        long out = targetOffset;
        int accumulator = 0;
        int bits = 0;
        for (int i = 0; i < length; i++) {
            int c = byteAt(source, offset + i) & 0xff;
            if (c == '=') {
                break;
            }
            int value = VALUES[c];
            if (value < 0) {
                if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
                    continue;
                }
                throw new IllegalArgumentException(
                        "not a base64 character at position " + i + ": 0x" + Integer.toHexString(c));
            }
            accumulator = (accumulator << 6) | value;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                setByte(target, out++, (byte) (accumulator >>> bits));
            }
        }
        return (int) (out - targetOffset);
    }

    private static byte byteAt(MemorySegment segment, long offset) {
        return segment.get(ValueLayout.JAVA_BYTE, offset);
    }

    private static void setByte(MemorySegment segment, long offset, byte value) {
        segment.set(ValueLayout.JAVA_BYTE, offset, value);
    }
}
