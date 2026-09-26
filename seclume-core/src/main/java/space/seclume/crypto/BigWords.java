package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Unsigned big numbers in off-heap memory.
 *
 * <p>{@link java.math.BigInteger} is inadmissible here: it is immutable, lives
 * on the heap as an {@code int[]}, and every operation creates further
 * intermediate values that no caller can ever erase again. With RSA it is the
 * password itself that goes through this computation (MySQL encrypts it with
 * the server public key for {@code caching_sha2_password}), so what is needed
 * is arithmetic whose intermediate values can be zeroed.
 *
 * <p>Representation: {@code n} words of 32 bits, least significant word first
 * (little-endian word order), each word stored little-endian. The word count is
 * not held in memory but passed along everywhere - in an RSA computation the
 * numbers have a fixed size anyway.
 */
final class BigWords {

    private BigWords() {
    }

    static int wordCount(int byteLength) {
        return (byteLength + 3) / 4;
    }

    static int get(MemorySegment a, int index) {
        return a.get(BlockDigest.LE_INT, index * 4L);
    }

    static void set(MemorySegment a, int index, int value) {
        a.set(BlockDigest.LE_INT, index * 4L, value);
    }

    /** Reads big-endian bytes, padded with zeroes on the left. */
    static void fromBytes(MemorySegment source, long offset, int length,
                          MemorySegment target, int words) {
        target.asSlice(0, words * 4L).fill((byte) 0);
        for (int i = 0; i < length; i++) {
            int value = source.get(ValueLayout.JAVA_BYTE, offset + length - 1 - i) & 0xff;
            int word = i / 4;
            int shift = (i % 4) * 8;
            set(target, word, get(target, word) | (value << shift));
        }
    }

    /** Writes out as big-endian bytes of a fixed length. */
    static void toBytes(MemorySegment source, int words,
                        MemorySegment target, long offset, int length) {
        for (int i = 0; i < length; i++) {
            int byteIndex = length - 1 - i;
            int word = i / 4;
            int shift = (i % 4) * 8;
            byte value = word < words ? (byte) (get(source, word) >>> shift) : 0;
            target.set(ValueLayout.JAVA_BYTE, offset + byteIndex, value);
        }
    }

    /** -1, 0 or 1 like {@code Integer.compare}, without an unnecessary early exit. */
    static int compare(MemorySegment a, MemorySegment b, int words) {
        for (int i = words - 1; i >= 0; i--) {
            int x = get(a, i);
            int y = get(b, i);
            if (x != y) {
                return Integer.compareUnsigned(x, y);
            }
        }
        return 0;
    }

    /** {@code a -= b} if {@code a >= b}, else nothing - in constant time. */
    static void subtractIfNotBelow(MemorySegment a, MemorySegment b, int words) {
        long borrow = 0;
        for (int i = 0; i < words; i++) {
            long difference = (get(a, i) & 0xffffffffL) - (get(b, i) & 0xffffffffL) - borrow;
            borrow = (difference >> 32) & 1;
        }
        int keep = (int) borrow - 1;               // all ones when a >= b, else zero
        borrow = 0;
        for (int i = 0; i < words; i++) {
            int x = get(a, i);
            long difference = (x & 0xffffffffL) - (get(b, i) & 0xffffffffL) - borrow;
            borrow = (difference >> 32) & 1;
            set(a, i, ((int) difference & keep) | (x & ~keep));
        }
    }

    /** {@code a -= b}, both {@code words} long; expects {@code a >= b}. */
    static void subtract(MemorySegment a, MemorySegment b, int words) {
        long borrow = 0;
        for (int i = 0; i < words; i++) {
            long difference = (get(a, i) & 0xffffffffL) - (get(b, i) & 0xffffffffL) - borrow;
            set(a, i, (int) difference);
            borrow = (difference >> 32) & 1;
        }
    }

    /** {@code a <<= 1}; the bit shifted out is lost. */
    static void shiftLeftOne(MemorySegment a, int words) {
        int carry = 0;
        for (int i = 0; i < words; i++) {
            int value = get(a, i);
            set(a, i, (value << 1) | carry);
            carry = value >>> 31;
        }
    }

    /**
     * Schoolbook multiplication: {@code out} needs {@code aWords + bWords} words.
     *
     * <p>The same work for every value - no skipped zero words, no carry loop
     * that runs as long as the carry does - because the numbers multiplied
     * here carry the password (see the class comment). Row {@code i} ends in
     * word {@code i + bWords}, which no earlier row has written, so its carry
     * is stored there directly.
     */
    static void multiply(MemorySegment a, int aWords, MemorySegment b, int bWords,
                         MemorySegment out) {
        out.asSlice(0, (aWords + bWords) * 4L).fill((byte) 0);
        for (int i = 0; i < aWords; i++) {
            long carry = 0;
            long factor = get(a, i) & 0xffffffffL;
            for (int j = 0; j < bWords; j++) {
                long product = factor * (get(b, j) & 0xffffffffL)
                        + (get(out, i + j) & 0xffffffffL) + carry;
                set(out, i + j, (int) product);
                carry = product >>> 32;
            }
            set(out, i + bWords, (int) carry);
        }
    }

    static boolean bit(MemorySegment a, int index) {
        return ((get(a, index >>> 5) >>> (index & 31)) & 1) != 0;
    }

    static void setSmall(MemorySegment a, int words, int value) {
        a.asSlice(0, words * 4L).fill((byte) 0);
        set(a, 0, value);
    }

    /**
     * {@code x mod modulus}, result in {@code result} ({@code words} words).
     *
     * <p>Schoolbook division, bit by bit from the top: no estimation, no
     * correction steps, no special cases - slower than Knuth's algorithm D, but
     * with one handshake per connection that does not matter, and the chance of
     * getting it wrong is markedly smaller.
     */
    static void mod(MemorySegment x, int xWords, MemorySegment modulus, int words,
                    MemorySegment result, Arena arena) {
        int extended = words + 1;
        MemorySegment remainder = arena.allocate(extended * 4L);
        MemorySegment modulusExtended = arena.allocate(extended * 4L);
        try {
            MemorySegment.copy(modulus, 0, modulusExtended, 0, words * 4L);
            set(modulusExtended, words, 0);
            remainder.fill((byte) 0);

            // Constant time: the next bit is ORed in rather than tested, and
            // the modulus is always subtracted, the result kept by a mask
            // when there was no borrow - no branch on the value being reduced.
            for (int bit = xWords * 32 - 1; bit >= 0; bit--) {
                shiftLeftOne(remainder, extended);
                set(remainder, 0, get(remainder, 0)
                        | ((get(x, bit >>> 5) >>> (bit & 31)) & 1));
                subtractIfNotBelow(remainder, modulusExtended, extended);
            }
            MemorySegment.copy(remainder, 0, result, 0, words * 4L);
        } finally {
            remainder.fill((byte) 0);
            modulusExtended.fill((byte) 0);
        }
    }

    /**
     * {@code base^exponent mod modulus}, all off-heap.
     *
     * @param exponent big-endian bytes, small (typically 65537 with RSA)
     */
    static void modPow(MemorySegment base, MemorySegment exponent, long exponentOffset,
                       int exponentLength, MemorySegment modulus, int words,
                       MemorySegment result, Arena arena) {
        MemorySegment accumulator = arena.allocate(words * 4L);
        MemorySegment product = arena.allocate(words * 8L);
        MemorySegment baseReduced = arena.allocate(words * 4L);
        try {
            mod(base, words, modulus, words, baseReduced, arena);
            setSmall(accumulator, words, 1);

            boolean started = false;
            for (int i = 0; i < exponentLength; i++) {
                int value = exponent.get(ValueLayout.JAVA_BYTE, exponentOffset + i) & 0xff;
                for (int bit = 7; bit >= 0; bit--) {
                    boolean isSet = ((value >>> bit) & 1) != 0;
                    if (!started) {
                        // Skip leading zero bits; squaring would be pointless.
                        if (!isSet) {
                            continue;
                        }
                        started = true;
                        MemorySegment.copy(baseReduced, 0, accumulator, 0, words * 4L);
                        continue;
                    }
                    multiply(accumulator, words, accumulator, words, product);
                    mod(product, 2 * words, modulus, words, accumulator, arena);
                    if (isSet) {
                        multiply(accumulator, words, baseReduced, words, product);
                        mod(product, 2 * words, modulus, words, accumulator, arena);
                    }
                }
            }
            MemorySegment.copy(accumulator, 0, result, 0, words * 4L);
        } finally {
            accumulator.fill((byte) 0);
            product.fill((byte) 0);
            baseReduced.fill((byte) 0);
        }
    }
}
