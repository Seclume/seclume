package space.seclume.crypto;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Comparisons whose running time does not depend on the content.
 *
 * <p>Every comparison that touches a secret, or anything derived from one, goes
 * through here. An early {@code return false} at the first differing byte
 * reveals through timing how many bytes matched - with a server proof that is
 * enough to guess it byte by byte.
 */
public final class ConstantTime {

    private ConstantTime() {
    }

    /** Equality of two ranges of the same length, without an early exit. */
    public static boolean equals(MemorySegment a, long aOffset,
                                 MemorySegment b, long bOffset, long length) {
        int difference = 0;
        for (long i = 0; i < length; i++) {
            int x = a.get(ValueLayout.JAVA_BYTE, aOffset + i) & 0xff;
            int y = b.get(ValueLayout.JAVA_BYTE, bOffset + i) & 0xff;
            difference |= x ^ y;
        }
        return difference == 0;
    }

    /** Equality of two segments - differing lengths are never equal. */
    public static boolean equals(MemorySegment a, MemorySegment b) {
        if (a.byteSize() != b.byteSize()) {
            return false;
        }
        return equals(a, 0, b, 0, a.byteSize());
    }
}
