package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * PBKDF2-HMAC (RFC 8018) off-heap.
 *
 * <p>PostgreSQL needs it for the SCRAM salted password, Oracle for the 12c
 * verifier, and MariaDB for {@code parsec}.
 */
public final class Pbkdf2 {

    private Pbkdf2() {
    }

    /**
     * Derives {@code out.byteSize()} bytes from {@code password} and
     * {@code salt}. Every intermediate value lives off-heap and is zeroed.
     *
     * @param iterations the round count, at least 1
     */
    public static void derive(HashAlgorithm algorithm,
                              MemorySegment password,
                              MemorySegment salt,
                              int iterations,
                              MemorySegment out) {
        if (iterations < 1) {
            throw new IllegalArgumentException("iterations must be at least 1");
        }
        long outputLength = out.byteSize();
        if (outputLength == 0) {
            return;
        }
        int hashLength = algorithm.digestLength();
        long blocks = (outputLength + hashLength - 1) / hashLength;
        if (blocks > 0xffffffffL) {
            throw new IllegalArgumentException("derived key too long");
        }

        try (Arena arena = Arena.ofConfined();
             Hmac hmac = new Hmac(algorithm, password)) {
            MemorySegment u = arena.allocate(hashLength);
            MemorySegment t = arena.allocate(hashLength);
            MemorySegment counter = arena.allocate(4);
            try {
                for (long block = 1; block <= blocks; block++) {
                    counter.set(ValueLayout.JAVA_BYTE, 0, (byte) (block >>> 24));
                    counter.set(ValueLayout.JAVA_BYTE, 1, (byte) (block >>> 16));
                    counter.set(ValueLayout.JAVA_BYTE, 2, (byte) (block >>> 8));
                    counter.set(ValueLayout.JAVA_BYTE, 3, (byte) block);

                    hmac.update(salt);
                    hmac.update(counter);
                    hmac.doFinal(u, 0);
                    MemorySegment.copy(u, 0, t, 0, hashLength);

                    for (int round = 1; round < iterations; round++) {
                        hmac.update(u);
                        hmac.doFinal(u, 0);
                        xorInto(t, u, hashLength);
                    }

                    long offset = (block - 1) * hashLength;
                    long take = Math.min(hashLength, outputLength - offset);
                    MemorySegment.copy(t, 0, out, offset, take);
                }
            } finally {
                u.fill((byte) 0);
                t.fill((byte) 0);
                counter.fill((byte) 0);
            }
        }
    }

    private static void xorInto(MemorySegment target, MemorySegment source, int length) {
        for (int i = 0; i < length; i++) {
            byte a = target.get(ValueLayout.JAVA_BYTE, i);
            byte b = source.get(ValueLayout.JAVA_BYTE, i);
            target.set(ValueLayout.JAVA_BYTE, i, (byte) (a ^ b));
        }
    }
}
