package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * The operating system's PBKDF2 gives exactly what this library's own code
 * gives - for the hashes, round counts and lengths the logins use, and for a
 * result longer than one hash, where the block counter matters.
 *
 * <p>Where OpenSSL 3 or CNG is there, the native path has to be taken: a
 * {@code derive} that quietly answered false would fall back to the slower
 * Java code and no assertion on the result would notice.
 */
@Isolated("sets seclume.crypto.pbkdf2 for the whole JVM")
class NativePbkdf2Test {

    /**
     * Whether the native path takes this hash here: OpenSSL takes all four,
     * CNG only SHA-1 and SHA-256 - its SHA-384 and SHA-512 were slower than
     * the Java code, so they are left to it on purpose.
     */
    private static boolean nativeExpected(HashAlgorithm algorithm) {
        if (OpenSslSigningKey.available()) {
            return true;
        }
        return CngSigningKey.available()
                && (algorithm == HashAlgorithm.SHA_1 || algorithm == HashAlgorithm.SHA_256);
    }

    @ParameterizedTest(name = "{0}, {1} rounds, {2} bytes")
    @CsvSource({
        "SHA_256, 4096, 32",
        "SHA_256, 1, 80",
        "SHA_1, 2, 20",
        "SHA_512, 4096, 64",
        "SHA_512, 3, 32",
        "SHA_384, 10, 100",
    })
    void nativeAndJavaAgree(HashAlgorithm algorithm, int iterations, int length) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment password = arena.allocateFrom(ValueLayout.JAVA_BYTE,
                    "not-a-secret-password".getBytes(StandardCharsets.UTF_8));
            MemorySegment salt = arena.allocateFrom(ValueLayout.JAVA_BYTE,
                    "salt-of-sixteen!".getBytes(StandardCharsets.UTF_8));
            MemorySegment fromNative = arena.allocate(length);
            MemorySegment fromJava = arena.allocate(length);

            boolean nativeDidIt = NativePbkdf2.derive(algorithm, password, salt, iterations,
                    fromNative);
            if (nativeExpected(algorithm)) {
                assertTrue(nativeDidIt, "the native library is here, yet " + algorithm
                        + " was not derived natively");
            }
            Assumptions.assumeTrue(nativeDidIt, "no native PBKDF2 for " + algorithm + " here");
            Pbkdf2.deriveInJava(algorithm, password, salt, iterations, fromJava);

            assertArrayEquals(fromJava.toArray(ValueLayout.JAVA_BYTE),
                    fromNative.toArray(ValueLayout.JAVA_BYTE));
            assertTrue(fromNative.toArray(ValueLayout.JAVA_BYTE)[0] != 0
                    || fromNative.toArray(ValueLayout.JAVA_BYTE)[1] != 0, "nothing was written");
        }
    }

    /** {@code -Dseclume.crypto.pbkdf2=java} turns the native path off, and nothing is written. */
    @Test
    void javaByPropertyWritesNothing() {
        String before = System.getProperty("seclume.crypto.pbkdf2");
        System.setProperty("seclume.crypto.pbkdf2", "java");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(32);
            assertFalse(NativePbkdf2.derive(HashAlgorithm.SHA_256, arena.allocate(8),
                    arena.allocate(16), 1, out));
            assertEquals(0, out.toArray(ValueLayout.JAVA_BYTE)[0] | out.toArray(
                    ValueLayout.JAVA_BYTE)[31]);
        } finally {
            if (before == null) {
                System.clearProperty("seclume.crypto.pbkdf2");
            } else {
                System.setProperty("seclume.crypto.pbkdf2", before);
            }
        }
    }

    /**
     * Inputs or outputs past what an {@code int} length can say are left to
     * the Java code: the libraries take an int. Sized views of address 0, never
     * touched - the refusal comes before any library call.
     */
    @Test
    void lengthsAnIntCannotSayAreRefused() {
        long tooLong = Integer.MAX_VALUE + 1L;
        MemorySegment huge = MemorySegment.NULL.reinterpret(tooLong);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment small = arena.allocate(16);
            assertFalse(NativePbkdf2.derive(HashAlgorithm.SHA_256, huge, small, 1, small));
            assertFalse(NativePbkdf2.derive(HashAlgorithm.SHA_256, small, huge, 1, small));
            assertFalse(NativePbkdf2.derive(HashAlgorithm.SHA_256, small, small, 1, huge));
        }
    }
}
