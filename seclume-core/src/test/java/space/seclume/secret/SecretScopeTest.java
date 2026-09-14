package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import space.seclume.Segments;

class SecretScopeTest {

    /**
     * The zeroing proof. The arena belongs to the test here, so the segment is
     * still readable after {@code close()} - and has to be zero then.
     */
    @Test
    void closeZeroesTheSegment() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment view;
            try (SecretScope scope = SecretScope.in(arena, 32)) {
                MemorySegment secret = scope.segment();
                MemorySegment.copy(Segments.ascii(arena, "hunter2-hunter2-hunter2-hunter2!"), 0,
                        secret, 0, 32);
                scope.length(32);
                assertEquals("hunter2-hunter2-hunter2-hunter2!",
                        new String(Segments.toBytes(scope.secret()), StandardCharsets.US_ASCII));
                view = secret;
            }
            for (long i = 0; i < view.byteSize(); i++) {
                assertEquals(0, view.get(ValueLayout.JAVA_BYTE, i), "byte " + i + " is not zero");
            }
        }
    }

    @Test
    void fromProviderFillsAndReportsLength() {
        try (SecretScope scope = SecretScope.fromProvider(
                new CallbackSecretProvider(64, target -> {
                    target.set(ValueLayout.JAVA_BYTE, 0, (byte) 'a');
                    target.set(ValueLayout.JAVA_BYTE, 1, (byte) 'b');
                    return 2;
                }))) {
            assertEquals(2, scope.length());
            assertEquals("6162", Segments.toHex(scope.secret()));
        }
    }

    /** If the provider fails, no open segment is left behind. */
    @Test
    void failingProviderReleasesTheScope() {
        long before = SecretScope.allocations();
        assertThrows(SecretUnavailableException.class, () -> SecretScope.fromProvider(
                new CallbackSecretProvider(16, target -> {
                    throw new SecretUnavailableException("nope");
                })));
        assertEquals(before + 1, SecretScope.allocations());
    }

    @Test
    void closedScopeRefusesAccess() {
        SecretScope scope = SecretScope.allocate(16);
        scope.close();
        scope.close();
        assertThrows(IllegalStateException.class, scope::secret);
        assertThrows(IllegalStateException.class, scope::segment);
    }

    /** No {@code toString} may show the content. */
    @Test
    void toStringHasNoContent() {
        try (Arena arena = Arena.ofConfined();
             SecretScope scope = SecretScope.in(arena, 8)) {
            MemorySegment.copy(Segments.ascii(arena, "secret!!"), 0, scope.segment(), 0, 8);
            scope.length(8);
            assertFalse(scope.toString().contains("secret"));
            assertTrue(scope.toString().startsWith("SecretScope["));
        }
    }

    @Test
    void allocationCounterCountsEveryScope() {
        long before = SecretScope.allocations();
        try (SecretScope first = SecretScope.allocate(8);
             SecretScope second = SecretScope.allocate(8)) {
            assertTrue(first.length() == 0 && second.length() == 0);
        }
        assertEquals(before + 2, SecretScope.allocations());
    }
}
