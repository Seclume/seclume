package space.seclume.internal;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Conversion between UTF-8 and UTF-16LE, off-heap.
 *
 * <p>Unavoidable in two places: Windows hands out secrets as UTF-16LE (DPAPI
 * and the Credential Manager store what a {@code SecureString} contained), and
 * TDS wants the password in the {@code LOGIN7} packet as UTF-16LE as well.
 * {@code new String(bytes, UTF_16LE).getBytes(UTF_8)} would be the usual route
 * and puts the password on the heap twice on the way.
 */
public final class Utf {

    private Utf() {
    }

    /**
     * UTF-16LE to UTF-8.
     *
     * @return the length of the UTF-8 form in bytes
     */
    public static int utf16LeToUtf8(MemorySegment source, long offset, int lengthInBytes,
                                    MemorySegment target, long targetOffset) {
        if ((lengthInBytes & 1) != 0) {
            throw new IllegalArgumentException("UTF-16LE needs an even number of bytes");
        }
        long out = targetOffset;
        int i = 0;
        while (i < lengthInBytes) {
            int unit = readUnit(source, offset + i);
            i += 2;
            int codePoint = unit;
            if (unit >= 0xd800 && unit <= 0xdbff && i < lengthInBytes) {
                int low = readUnit(source, offset + i);
                if (low >= 0xdc00 && low <= 0xdfff) {
                    codePoint = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                    i += 2;
                }
            }
            out = writeUtf8(target, out, codePoint);
        }
        return (int) (out - targetOffset);
    }

    /**
     * UTF-8 to UTF-16LE.
     *
     * @return the length of the UTF-16LE form in bytes
     */
    public static int utf8ToUtf16Le(MemorySegment source, long offset, int lengthInBytes,
                                    MemorySegment target, long targetOffset) {
        long out = targetOffset;
        int i = 0;
        while (i < lengthInBytes) {
            int first = byteAt(source, offset + i) & 0xff;
            int codePoint;
            int size;
            if (first < 0x80) {
                codePoint = first;
                size = 1;
            } else if ((first & 0xe0) == 0xc0) {
                codePoint = first & 0x1f;
                size = 2;
            } else if ((first & 0xf0) == 0xe0) {
                codePoint = first & 0x0f;
                size = 3;
            } else {
                codePoint = first & 0x07;
                size = 4;
            }
            if (i + size > lengthInBytes) {
                throw new IllegalArgumentException("truncated UTF-8 sequence");
            }
            for (int k = 1; k < size; k++) {
                codePoint = (codePoint << 6) | (byteAt(source, offset + i + k) & 0x3f);
            }
            i += size;

            if (codePoint < 0x10000) {
                writeUnit(target, out, codePoint);
                out += 2;
            } else {
                int value = codePoint - 0x10000;
                writeUnit(target, out, 0xd800 + (value >>> 10));
                writeUnit(target, out + 2, 0xdc00 + (value & 0x3ff));
                out += 4;
            }
        }
        return (int) (out - targetOffset);
    }

    /** How many bytes {@link #utf8ToUtf16Le} writes at most. */
    public static int utf16LeUpperBound(int utf8Length) {
        return utf8Length * 2;
    }

    /** How many bytes {@link #utf16LeToUtf8} writes at most. */
    public static int utf8UpperBound(int utf16Length) {
        // One UTF-16 code unit (2 bytes) becomes at most 3 UTF-8 bytes;
        // a surrogate pair (4 bytes) at most 4.
        return (utf16Length / 2) * 3;
    }

    private static long writeUtf8(MemorySegment target, long out, int codePoint) {
        if (codePoint < 0x80) {
            setByte(target, out, (byte) codePoint);
            return out + 1;
        }
        if (codePoint < 0x800) {
            setByte(target, out, (byte) (0xc0 | (codePoint >>> 6)));
            setByte(target, out + 1, (byte) (0x80 | (codePoint & 0x3f)));
            return out + 2;
        }
        if (codePoint < 0x10000) {
            setByte(target, out, (byte) (0xe0 | (codePoint >>> 12)));
            setByte(target, out + 1, (byte) (0x80 | ((codePoint >>> 6) & 0x3f)));
            setByte(target, out + 2, (byte) (0x80 | (codePoint & 0x3f)));
            return out + 3;
        }
        setByte(target, out, (byte) (0xf0 | (codePoint >>> 18)));
        setByte(target, out + 1, (byte) (0x80 | ((codePoint >>> 12) & 0x3f)));
        setByte(target, out + 2, (byte) (0x80 | ((codePoint >>> 6) & 0x3f)));
        setByte(target, out + 3, (byte) (0x80 | (codePoint & 0x3f)));
        return out + 4;
    }

    private static int readUnit(MemorySegment segment, long offset) {
        return (byteAt(segment, offset) & 0xff) | ((byteAt(segment, offset + 1) & 0xff) << 8);
    }

    private static void writeUnit(MemorySegment segment, long offset, int unit) {
        setByte(segment, offset, (byte) unit);
        setByte(segment, offset + 1, (byte) (unit >>> 8));
    }

    private static byte byteAt(MemorySegment segment, long offset) {
        return segment.get(ValueLayout.JAVA_BYTE, offset);
    }

    private static void setByte(MemorySegment segment, long offset, byte value) {
        segment.set(ValueLayout.JAVA_BYTE, offset, value);
    }
}
