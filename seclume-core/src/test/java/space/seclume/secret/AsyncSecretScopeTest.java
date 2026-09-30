package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;

/** SEC-02: ordinary allocation and provider scopes must support async cleanup. */
@Isolated
@Timeout(30)
@SuppressWarnings("try") // Explicit async close plus owner cleanup is the regression under test.
class AsyncSecretScopeTest {
    @Test
    void timeoutThreadReleasesDefaultAllocation() throws Exception {
        long before = SecretScope.open();
        try (SecretScope scope = SecretScope.allocate(64)) {
            MemorySegment view = scope.segment();
            view.fill((byte) 0x5a);
            scope.length(64);
            runOnOtherThread(scope::close);
            assertFalse(view.scope().isAlive());
            assertThrows(IllegalStateException.class, scope::secret);
            assertEquals(before, SecretScope.open());
        }
        assertEquals(before, SecretScope.open(), "owner cleanup must not close twice");
    }

    @Test
    void providerScopeCanBeReadAndClosedAfterThreadHandoff() throws Exception {
        long before = SecretScope.open();
        try (SecretScope scope = SecretScope.fromProvider(new CallbackSecretProvider(32, target -> {
            target.asSlice(0, 13).fill((byte) 0x37);
            return 13;
        }))) {
            runOnOtherThread(() -> {
                assertEquals(13, scope.length());
                assertEquals((byte) 0x37, scope.secret().get(ValueLayout.JAVA_BYTE, 12));
                scope.close();
            });
            assertEquals(before, SecretScope.open());
        }
    }

    @Test
    void asyncWipeCoversUnusedCapacityInCallerOwnedSharedArena() throws Exception {
        try (Arena arena = Arena.ofShared(); SecretScope scope = SecretScope.in(arena, 64)) {
            MemorySegment view = scope.segment();
            view.fill((byte) 0x5a);
            scope.length(7);
            runOnOtherThread(scope::close);
            assertEquals(-1L, view.mismatch(arena.allocate(64)), "entire allocation must be zero");
        }
    }

    @Test
    void everyConcurrentCloseReturnsOnlyAfterTheWipe() throws Exception {
        for (int round = 0; round < 20; round++) {
            long before = SecretScope.open();
            try (Arena arena = Arena.ofShared(); SecretScope scope = SecretScope.in(arena, 1024 * 1024)) {
                MemorySegment view = scope.segment();
                MemorySegment zero = arena.allocate(view.byteSize());
                view.fill((byte) 0x5a);
                CyclicBarrier start = new CyclicBarrier(4);
                AtomicReference<Throwable> failure = new AtomicReference<>();
                Thread[] closers = new Thread[4];
                for (int i = 0; i < closers.length; i++) {
                    closers[i] = Thread.ofVirtual().start(() -> {
                        try {
                            start.await();
                            scope.close();
                            assertEquals(-1L, view.mismatch(zero), "close returned before wiping finished");
                            assertEquals(before, SecretScope.open());
                        } catch (Throwable error) {
                            failure.compareAndSet(null, error);
                        }
                    });
                }
                for (Thread closer : closers) {
                    closer.join();
                }
                if (failure.get() != null) {
                    throw new AssertionError(failure.get());
                }
            }
            assertEquals(before, SecretScope.open());
        }
    }

    private static void runOnOtherThread(Runnable task) throws Exception {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread thread = Thread.ofVirtual().start(() -> {
            try {
                task.run();
            } catch (Throwable error) {
                failure.set(error);
            }
        });
        thread.join();
        if (failure.get() != null) {
            throw new AssertionError(failure.get());
        }
    }
}
