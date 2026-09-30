package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicReference;

import jdk.jfr.Recording;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The secret's lifecycle on the paths the audit of 27.09.2026 found open.
 *
 * <p>K1: an {@code Error} out of the provider. K2: the recording after a
 * fetch - the provider's own expiry code - throwing. And the shared scope
 * closed from two threads at once. Each asserts the one thing that matters:
 * no scope is left open, and none is closed twice.
 *
 * <p>No secret is materialised here: the providers write a fixed filler byte,
 * never a password.
 */
@Timeout(60)
@org.junit.jupiter.api.parallel.Isolated
class SecretLifecycleRegressionTest {

    private static final String EVENT = "space.seclume.CredentialRotation";

    /** Writes {@code n} filler bytes. */
    private static int fill(MemorySegment target, int n) {
        target.asSlice(0, n).fill((byte) 'x');
        return n;
    }

    // ---- K1 --------------------------------------------------------------

    @Test
    void anErrorFromTheProviderLeavesNothingOpen() {
        long open = SecretScope.open();

        assertThrows(OutOfMemoryError.class, () -> SecretScope.fromProvider(
                new CallbackSecretProvider(32, target -> {
                    fill(target, 8);                 // half a secret is already there
                    throw new OutOfMemoryError("simulated");
                })));

        assertEquals(open, SecretScope.open(), "the scope with half a secret in it stayed open");
    }

    @Test
    void aStackOverflowFromTheProviderLeavesNothingOpen() {
        long open = SecretScope.open();

        assertThrows(StackOverflowError.class, () -> SecretScope.fromProvider(
                new CallbackSecretProvider(32, target -> {
                    throw new StackOverflowError();
                })));

        assertEquals(open, SecretScope.open());
    }

    // ---- K2 --------------------------------------------------------------

    /** A provider whose expiry is its own code, and fails. */
    private static final class FailingExpiry implements SecretProvider, ExpiringCredentials {

        private final RuntimeException exception;
        private final Error error;

        FailingExpiry(RuntimeException exception, Error error) {
            this.exception = exception;
            this.error = error;
        }

        @Override
        public int writeSecret(MemorySegment target) {
            return fill(target, 16);
        }

        @Override
        public int maxSecretLength() {
            return 32;
        }

        @Override
        public Instant credentialsValidUntil() {
            if (error != null) {
                throw error;
            }
            throw exception;
        }
    }

    @Test
    void anExpiryThatThrowsDoesNotLoseTheScopeWhileRecording() {
        try (Recording recording = new Recording()) {
            recording.enable(EVENT);
            recording.start();
            long open = SecretScope.open();

            SecretScope scope = SecretScope.fromProvider(
                    new FailingExpiry(new IllegalStateException("expiry broken"), null));
            try {
                assertNotNull(scope, "the fetch succeeded, the recording failed - the "
                        + "scope has to come back anyway");
                assertEquals(16, scope.length());
                assertEquals(open + 1, SecretScope.open());
            } finally {
                scope.close();
            }
            assertEquals(open, SecretScope.open());
        }
    }

    @Test
    void anExpiryThatThrowsIsNotEvenAskedWhenNobodyRecords() {
        long open = SecretScope.open();
        try (SecretScope scope = SecretScope.fromProvider(
                new FailingExpiry(new IllegalStateException("expiry broken"), null))) {
            assertEquals(16, scope.length());
        }
        assertEquals(open, SecretScope.open());
    }

    @Test
    void anErrorFromTheRecordingClosesTheScopeItWouldHaveLost() {
        try (Recording recording = new Recording()) {
            recording.enable(EVENT);
            recording.start();
            long open = SecretScope.open();
            Error boom = new AssertionError("recording died");

            Error thrown = assertThrows(AssertionError.class, () -> SecretScope.fromProvider(
                    new FailingExpiry(null, boom)));

            assertSame(boom, thrown);
            assertEquals(open, SecretScope.open(), "nobody owns the scope, so it must be closed");
        }
    }

    @Test
    void aFailingProviderKeepsItsExceptionWhenTheRecordingFailsToo() {
        try (Recording recording = new Recording()) {
            recording.enable(EVENT);
            recording.start();
            long open = SecretScope.open();

            final class Both implements SecretProvider, ExpiringCredentials {
                @Override
                public int writeSecret(MemorySegment target) {
                    throw new SecretUnavailableException("the source is gone");
                }

                @Override
                public int maxSecretLength() {
                    return 16;
                }

                @Override
                public Instant credentialsValidUntil() {
                    throw new IllegalStateException("and so is its expiry");
                }
            }

            SecretUnavailableException thrown = assertThrows(SecretUnavailableException.class,
                    () -> SecretScope.fromProvider(new Both()));
            assertEquals(1, thrown.getSuppressed().length,
                    "the recording's failure is attached, not substituted");
            assertEquals(open, SecretScope.open());
        }
    }

    // ---- N2: the shared scope, closed from two threads -------------------

    @Test
    void aSharedScopeClosedFromManyThreadsAtOnceClosesExactlyOnce() throws Exception {
        for (int round = 0; round < 200; round++) {
            long open = SecretScope.open();
            SecretScope scope = SecretScope.allocateShared(64);
            fill(scope.segment(), 64);
            int threads = 4;
            CyclicBarrier start = new CyclicBarrier(threads);
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread[] closers = new Thread[threads];
            for (int t = 0; t < threads; t++) {
                closers[t] = Thread.ofPlatform().start(() -> {
                    try {
                        start.await();
                        scope.close();
                    } catch (Throwable e) {
                        failure.compareAndSet(null, e);
                    }
                });
            }
            for (Thread closer : closers) {
                closer.join();
            }
            if (failure.get() != null) {
                throw new AssertionError("a concurrent close failed", failure.get());
            }
            assertEquals(open, SecretScope.open(),
                    "round " + round + ": closed more or less than once");
        }
    }

    @Test
    void aSharedScopeIsUnusableOnceAnotherThreadClosedIt() throws Exception {
        SecretScope scope = SecretScope.allocateShared(16);
        fill(scope.segment(), 16);
        scope.length(16);
        CountDownLatch closed = new CountDownLatch(1);
        Thread.ofPlatform().start(() -> {
            scope.close();
            closed.countDown();
        });
        assertTrue(closed.await(10, java.util.concurrent.TimeUnit.SECONDS));
        assertThrows(IllegalStateException.class, scope::secret);
        scope.close();                                 // and closing again stays harmless
    }

    @Test
    void aScopeWrittenOnOneThreadIsReadAndWipedOnAnother() throws Exception {
        long open = SecretScope.open();
        SecretScope scope = SecretScope.allocateShared(16);
        scope.length(fill(scope.segment(), 16));
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread other = Thread.ofPlatform().start(() -> {
            try {
                MemorySegment secret = scope.secret();
                assertEquals('x', secret.get(ValueLayout.JAVA_BYTE, 0));
                scope.close();
            } catch (Throwable e) {
                failure.set(e);
            }
        });
        other.join();
        if (failure.get() != null) {
            throw new AssertionError(failure.get());
        }
        assertEquals(open, SecretScope.open());
    }
}
