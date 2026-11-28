package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.function.Predicate;

import org.junit.jupiter.api.Test;

/**
 * Each system source on its own, where the platform has it: a source that
 * silently failed would hide behind the next one, and the fallback array
 * would be the only randomness without anyone noticing.
 */
class EntropySourcesTest {

    @Test
    void thePlatformsOwnSourceFillsLargeAndOddSizes() {
        Predicate<MemorySegment> source = Platform.isWindows() ? Entropy::fillFromBCrypt
                : Platform.isLinux() ? Entropy::fillFromGetrandom
                : Platform.isMac() ? Entropy::fillFromGetentropy
                : Entropy::fillFromUrandom;
        // 1000 crosses getentropy's 256-byte limit; 1 << 20 a short getrandom read.
        for (int size : new int[] {1, 257, 1000, 1 << 20}) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment first = arena.allocate(size);
                MemorySegment second = arena.allocate(size);
                assertTrue(source.test(first), "no randomness from the system for " + size);
                assertTrue(source.test(second));
                if (size >= 257) {
                    assertFalse(first.mismatch(second) == -1, "the same bytes twice");
                    assertTrue(notAllZero(first.asSlice(size - 32)),
                            "the tail of " + size + " bytes was never written");
                }
            }
        }
    }

    @Test
    void urandomStillWorksAsTheFallbackOffWindows() {
        if (Platform.isWindows()) {
            return;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(4096);
            assertTrue(Entropy.fillFromUrandom(target));
            assertTrue(notAllZero(target));
        }
    }

    private static boolean notAllZero(MemorySegment segment) {
        for (long i = 0; i < segment.byteSize(); i++) {
            if (segment.get(java.lang.foreign.ValueLayout.JAVA_BYTE, i) != 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * The last resort - a SecureRandom, where no kernel source answers - gives
     * fresh bytes each time, and is never what the normal path takes on a
     * platform that has one.
     */
    @Test
    void theFallbackIsFreshAndNeverTheNormalPath() {
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            java.lang.foreign.MemorySegment a = arena.allocate(32);
            java.lang.foreign.MemorySegment b = arena.allocate(32);
            Entropy.fillFromSecureRandom(a);
            Entropy.fillFromSecureRandom(b);
            org.junit.jupiter.api.Assertions.assertNotEquals(-1L, a.mismatch(b),
                    "two fallback fills gave the same bytes");
            long before = Entropy.fallbackUses();
            for (int i = 0; i < 64; i++) {
                Entropy.fill(arena.allocate(4096));
            }
            org.junit.jupiter.api.Assertions.assertEquals(before, Entropy.fallbackUses(),
                    "the normal path took the last resort on a platform with a kernel source");
        }
    }
}
