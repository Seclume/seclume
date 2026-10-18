package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * The operating system's PBKDF2 gives exactly what this library's own code
 * gives - for the hashes, round counts and lengths the logins use, and for a
 * result longer than one hash, where the block counter matters.
 */
class NativePbkdf2Test {

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
            Assumptions.assumeTrue(nativeDidIt, "no native PBKDF2 for " + algorithm + " here");
            Pbkdf2.deriveInJava(algorithm, password, salt, iterations, fromJava);

            assertArrayEquals(fromJava.toArray(ValueLayout.JAVA_BYTE),
                    fromNative.toArray(ValueLayout.JAVA_BYTE));
            assertTrue(fromNative.toArray(ValueLayout.JAVA_BYTE)[0] != 0
                    || fromNative.toArray(ValueLayout.JAVA_BYTE)[1] != 0, "nothing was written");
        }
    }
}
