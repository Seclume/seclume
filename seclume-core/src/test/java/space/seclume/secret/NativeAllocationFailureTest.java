package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * Native memory running out at the moment a secret's segment is allocated.
 *
 * <p>Provoking that for real does not test seclume: when the operating system
 * refuses memory, HotSpot itself usually cannot go on and the JVM ends with
 * an error report (tried 2026-10-30: 16 KB scopes until the machine's limit,
 * {@code os::commit_memory failed}). The secrets then end with the process,
 * and the kernel zeroes the pages before anyone else gets them. What can be
 * tested is the case that comes back as an {@link OutOfMemoryError}: an
 * arena whose allocation throws it, at the first allocation and after some
 * that succeeded.
 *
 * <p>What has to hold: the error arrives as itself; the scope that could not
 * be made leaves nothing open and counts nothing; a caller's arena is not
 * closed by a scope that never owned it; the scopes made before stay whole
 * and close; and after the failure, memory is used again normally.
 * Isolated: {@link SecretScope#open()} is one count for the whole JVM.
 */
@Isolated
class NativeAllocationFailureTest {

    /** An arena that refuses its {@code n}-th allocation, as malloc would. */
    private static final class Refusing implements Arena {
        private final Arena real = Arena.ofShared();
        private final AtomicInteger left;
        private boolean closed;

        Refusing(int allocationsBeforeFailing) {
            this.left = new AtomicInteger(allocationsBeforeFailing);
        }

        @Override
        public MemorySegment allocate(long byteSize, long byteAlignment) {
            if (left.getAndDecrement() <= 0) {
                throw new OutOfMemoryError("native memory refused, as a test");
            }
            return real.allocate(byteSize, byteAlignment);
        }

        @Override
        public MemorySegment.Scope scope() {
            return real.scope();
        }

        @Override
        public void close() {
            closed = true;
            real.close();
        }
    }

    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();
    private static final byte[] CANARY = new byte[32];

    static {
        RANDOM.nextBytes(CANARY);
    }

    private static void fill(SecretScope scope) {
        MemorySegment.copy(CANARY, 0, scope.segment(), ValueLayout.JAVA_BYTE, 0, CANARY.length);
        scope.length(CANARY.length);
    }

    @Test
    void theFirstAllocationRefusedLeavesNothingOpen() {
        long openBefore = SecretScope.open();
        long allocationsBefore = SecretScope.allocations();
        Refusing arena = new Refusing(0);
        OutOfMemoryError refused = assertThrows(OutOfMemoryError.class,
                () -> SecretScope.in(arena, 64));
        assertEquals("native memory refused, as a test", refused.getMessage());
        assertEquals(openBefore, SecretScope.open(), "a scope that was never made is open");
        assertEquals(allocationsBefore, SecretScope.allocations());
        assertFalse(arena.closed, "a scope closed an arena it did not own");
        arena.close();
    }

    @Test
    void aRefusalAfterSomeScopesLeavesThoseWholeAndClosable() {
        long openBefore = SecretScope.open();
        Refusing arena = new Refusing(5);
        List<SecretScope> made = new ArrayList<>();
        OutOfMemoryError refused = null;
        for (int i = 0; i < 10 && refused == null; i++) {
            try {
                SecretScope scope = SecretScope.in(arena, 64);
                fill(scope);
                made.add(scope);
            } catch (OutOfMemoryError e) {
                refused = e;
            }
        }
        assertSame(OutOfMemoryError.class, refused == null ? null : refused.getClass(),
                "the sixth allocation was not refused");
        assertEquals(5, made.size());
        assertEquals(openBefore + 5, SecretScope.open(), "the refused scope counts as open");
        for (SecretScope scope : made) {
            MemorySegment secret = scope.secret();
            for (int i = 0; i < CANARY.length; i++) {
                assertEquals(CANARY[i], secret.get(ValueLayout.JAVA_BYTE, i),
                        "a scope made before the refusal was damaged");
            }
        }
        List<MemorySegment> segments = new ArrayList<>();
        for (SecretScope scope : made) {
            segments.add(scope.segment());
            scope.close();
        }
        // The arena is the test's, so the segments are still readable: zero.
        for (MemorySegment segment : segments) {
            for (long i = 0; i < segment.byteSize(); i++) {
                assertEquals(0, segment.get(ValueLayout.JAVA_BYTE, i), "byte " + i + " not wiped");
            }
        }
        assertEquals(openBefore, SecretScope.open());
        arena.close();

        // And afterwards memory is used again as ever.
        try (SecretScope again = SecretScope.allocate(64)) {
            fill(again);
            assertEquals(CANARY.length, again.length());
        }
        assertEquals(openBefore, SecretScope.open());
    }

    @Test
    void aProviderThatRunsOutOfMemoryHalfwayLeavesItsScopeWiped() {
        long openBefore = SecretScope.open();
        MemorySegment[] seen = new MemorySegment[1];
        SecretProvider halfway = new SecretProvider() {
            @Override
            public int maxSecretLength() {
                return 64;
            }

            @Override
            public int writeSecret(MemorySegment target) {
                MemorySegment.copy(CANARY, 0, target, ValueLayout.JAVA_BYTE, 0, 16);
                seen[0] = target;
                throw new OutOfMemoryError("ran out while decoding, as a test");
            }
        };
        assertThrows(OutOfMemoryError.class, () -> SecretScope.fromProvider(halfway));
        assertEquals(openBefore, SecretScope.open(), "the half-written scope is still open");
        assertTrue(seen[0] != null && !seen[0].scope().isAlive(),
                "the half-written scope's memory was not released");
    }
}
