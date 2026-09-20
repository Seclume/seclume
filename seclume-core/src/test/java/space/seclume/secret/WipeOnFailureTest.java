package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import space.seclume.Segments;

/**
 * The secret is wiped on the paths nobody plans for.
 *
 * <p>The happy path is covered several times over - by
 * {@code SecretScopeTest.closeZeroesTheSegment} for the zeroing itself and by
 * the heap dump harness for a whole login. What was never checked is the other
 * half, and it is the half where wipes actually get lost: <b>an early exit</b>.
 * A rejected password, a TLS handshake that fails, a timeout, a cancelled
 * statement, an interrupted thread, an exception thrown while the credential is
 * in hand - each of those leaves a method somewhere other than at its end, and
 * a wipe that is not attached to the exit does not happen.
 *
 * <p>Two different things are asserted here, and they are not interchangeable:
 *
 * <ul>
 *   <li><b>That the scope was closed at all.</b> Counted with
 *       {@link SecretScope#open()}, because after a real close the memory is
 *       released, and reading it would mean reading freed pages - a test that
 *       usually passes and occasionally takes the JVM down is worse than none.
 *   <li><b>That closing leaves zeroes.</b> Shown where the arena belongs to the
 *       test ({@link SecretScope#in}), so the segment stays mapped and can be
 *       read back byte by byte.
 * </ul>
 *
 * <p>Together they say "on this path the secret is gone". Apart, each is worth
 * little, which is why both appear.
 *
 * <p>The protocol-level counterparts - a server that rejects the login, one
 * that drops the connection mid-handshake, one that never answers - live with
 * their drivers, where there is a socket to misbehave on.
 */
class WipeOnFailureTest {

    private static final String SECRET = "hunter2-hunter2-hunter2-hunter2!";

    /** A provider that hands out the test password and nothing else. */
    private static SecretProvider provider() {
        return new CallbackSecretProvider(64, target -> {
            byte[] bytes = SECRET.getBytes(StandardCharsets.US_ASCII);
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
    }

    private static void assertAllZero(MemorySegment view) {
        for (long i = 0; i < view.byteSize(); i++) {
            assertEquals(0, view.get(ValueLayout.JAVA_BYTE, i), "byte " + i + " is not zero");
        }
    }

    // ------------------------------------------- the secret never arrives --

    @Test
    void aProviderThatFailsLeavesNothingOpen() {
        long open = SecretScope.open();

        assertThrows(SecretUnavailableException.class, () -> SecretScope.fromProvider(
                new CallbackSecretProvider(32, target -> {
                    // Half written, then the source gives up - the realistic
                    // shape of a mount disappearing or an agent dying.
                    target.set(ValueLayout.JAVA_BYTE, 0, (byte) 'h');
                    throw new SecretUnavailableException("the source went away");
                })));

        assertEquals(open, SecretScope.open());
    }

    /**
     * A provider that lies about the length is refused, and the segment it
     * wrote into is cleaned up anyway.
     *
     * <p>Worth its own test because the length is the one thing
     * {@code fromProvider} takes on trust, and the refusal happens after the
     * provider has already written.
     */
    @Test
    void aProviderThatReportsNonsenseLeavesNothingOpen() {
        long open = SecretScope.open();

        assertThrows(SecretUnavailableException.class, () -> SecretScope.fromProvider(
                new CallbackSecretProvider(16, target -> 9999)));

        assertEquals(open, SecretScope.open());
    }

    // -------------------------------------- the secret is there and fails --

    /**
     * An exception thrown while the credential is in hand.
     *
     * <p>The case the roadmap names explicitly, and the one every protocol
     * method is exposed to: the password has been read, the handshake is
     * halfway through, and the server says no.
     */
    @Test
    void anExceptionWhileTheSecretIsHeldStillWipesIt() {
        try (Arena arena = Arena.ofConfined()) {
            AtomicReference<MemorySegment> view = new AtomicReference<>();

            assertThrows(IllegalStateException.class, () -> {
                try (SecretScope scope = SecretScope.in(arena, 32)) {
                    MemorySegment.copy(Segments.ascii(arena, SECRET), 0, scope.segment(), 0, 32);
                    scope.length(32);
                    view.set(scope.segment());
                    throw new IllegalStateException("password authentication failed");
                }
            });

            assertAllZero(view.get());
        }
    }

    /**
     * An {@code Error}, not an exception.
     *
     * <p>Try-with-resources covers it, and that is worth stating rather than
     * assuming: a {@code StackOverflowError} out of a deep protocol call or an
     * {@code OutOfMemoryError} while a buffer grows are exactly the moments
     * when nobody is watching.
     */
    @Test
    void anErrorWipesItToo() {
        try (Arena arena = Arena.ofConfined()) {
            AtomicReference<MemorySegment> view = new AtomicReference<>();

            assertThrows(StackOverflowError.class, () -> {
                try (SecretScope scope = SecretScope.in(arena, 32)) {
                    MemorySegment.copy(Segments.ascii(arena, SECRET), 0, scope.segment(), 0, 32);
                    scope.length(32);
                    view.set(scope.segment());
                    throw new StackOverflowError();
                }
            });

            assertAllZero(view.get());
        }
    }

    /**
     * An interrupted thread.
     *
     * <p>A pool shutting down interrupts its workers, and a worker can be in
     * the middle of a login. Two things have to survive that: the wipe, and the
     * interrupt flag - swallowing the flag would leave the pool waiting for a
     * thread that no longer knows it should stop.
     */
    @Test
    void anInterruptedLoginWipesAndKeepsTheFlag() throws Exception {
        long open = SecretScope.open();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicBoolean flag = new AtomicBoolean();

        Thread worker = new Thread(() -> {
            try (SecretScope scope = SecretScope.fromProvider(provider())) {
                assertEquals(SECRET.length(), scope.length());
                Thread.currentThread().interrupt();
                throw new InterruptedException("cancelled while logging in");
            } catch (InterruptedException expected) {
                flag.set(Thread.currentThread().isInterrupted());
            } catch (Throwable t) {
                failure.set(t);
            }
        });
        worker.start();
        worker.join();

        assertNull(failure.get(), String.valueOf(failure.get()));
        assertTrue(flag.get(), "the interrupt flag was lost");
        assertEquals(open, SecretScope.open());
    }

    /**
     * A timeout, which is an exception on somebody else's clock.
     *
     * <p>Modelled rather than waited for: what is being checked is the shape of
     * the exit, not a number of milliseconds, and a test that sleeps for a
     * timeout is a test that eventually fails on a loaded build machine.
     */
    @Test
    void aTimeoutWipes() {
        long open = SecretScope.open();

        assertThrows(java.net.SocketTimeoutException.class, () -> {
            try (SecretScope scope = SecretScope.fromProvider(provider())) {
                assertEquals(SECRET.length(), scope.length());
                throw new java.net.SocketTimeoutException("read timed out");
            }
        });

        assertEquals(open, SecretScope.open());
    }

    /**
     * Nested scopes - the inner one fails and both are gone.
     *
     * <p>The shape {@link EncryptedSecretProvider} has: a ciphertext in one
     * scope, a key in another, and the failure arriving while both are open.
     */
    @Test
    void anInnerFailureClosesTheOuterScopeAsWell() {
        long open = SecretScope.open();

        assertThrows(SecretUnavailableException.class, () -> {
            try (SecretScope outer = SecretScope.fromProvider(provider())) {
                assertEquals(open + 1, SecretScope.open());
                assertEquals(SECRET.length(), outer.length());
                try (SecretScope inner = SecretScope.fromProvider(provider())) {
                    assertEquals(open + 2, SecretScope.open());
                    assertEquals(SECRET.length(), inner.length());
                    throw new SecretUnavailableException("the key did not fit");
                }
            }
        });

        assertEquals(open, SecretScope.open());
    }

    // ------------------------------------------- the encrypted provider ----

    /**
     * A ciphertext that does not authenticate leaves nothing open and writes
     * nothing.
     *
     * <p>The second half is the one with teeth. AES-GCM only knows whether a
     * ciphertext is genuine once it has processed all of it, so there is a
     * moment where the plaintext exists and the verdict does not. If that
     * plaintext reached the caller's segment, a forged ciphertext would hand
     * out whatever it happens to decrypt to - and a caller holding bytes that
     * look like a password sends them.
     */
    @Test
    void aForgedCiphertextWritesNothingAndLeavesNothingOpen() {
        long open = SecretScope.open();
        byte[] key = new byte[32];
        byte[] forged = new byte[12 + 24 + 16];
        for (int i = 0; i < forged.length; i++) {
            forged[i] = (byte) (i + 1);
        }

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(64);
            target.fill((byte) 0x5a); // recognisable, so an overwrite would show

            EncryptedSecretProvider provider = new EncryptedSecretProvider(
                    literal(Base64.getEncoder().encodeToString(forged)),
                    literal(Base64.getEncoder().encodeToString(key)),
                    null);

            SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                    () -> provider.writeSecret(target));
            assertTrue(refused.getMessage().contains("did not authenticate"));

            for (long i = 0; i < target.byteSize(); i++) {
                assertEquals((byte) 0x5a, target.get(ValueLayout.JAVA_BYTE, i),
                        "byte " + i + " was written although the tag failed");
            }
        }
        assertEquals(open, SecretScope.open());
    }

    /** The same for a key that is not a key: the scopes still go. */
    @Test
    void anUnusableKeyLeavesNothingOpen() {
        long open = SecretScope.open();
        byte[] whole = new byte[12 + 8 + 16];

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(64);
            EncryptedSecretProvider provider = new EncryptedSecretProvider(
                    literal(Base64.getEncoder().encodeToString(whole)),
                    literal(Base64.getEncoder().encodeToString(new byte[20])),
                    null);

            SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                    () -> provider.writeSecret(target));
            assertTrue(refused.getMessage().contains("16, 24 or 32"), refused.getMessage());
        }
        assertEquals(open, SecretScope.open());
    }

    /** And when the source of the ciphertext fails before any of that. */
    @Test
    void aFailingInnerSourceLeavesNothingOpen() {
        long open = SecretScope.open();

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(64);
            EncryptedSecretProvider provider = new EncryptedSecretProvider(
                    new CallbackSecretProvider(64, t -> {
                        throw new SecretUnavailableException("the ciphertext file is gone");
                    }),
                    literal(Base64.getEncoder().encodeToString(new byte[32])),
                    null);

            assertThrows(SecretUnavailableException.class, () -> provider.writeSecret(target));
        }
        assertEquals(open, SecretScope.open());
    }

    // -------------------------------------------------------- the gauge ----

    /**
     * That the gauge would notice.
     *
     * <p>Every assertion above is "the number came back to where it started",
     * and a gauge stuck at zero would satisfy all of them. So: open one without
     * closing it, watch the number rise, then close it.
     */
    @Test
    void theGaugeActuallyMoves() {
        long open = SecretScope.open();
        SecretScope scope = SecretScope.fromProvider(provider());
        assertEquals(open + 1, SecretScope.open(), "an open scope has to be visible");
        scope.close();
        assertEquals(open, SecretScope.open());
        scope.close();
        assertEquals(open, SecretScope.open(), "a second close must not count twice");
    }

    /** A Base64 string as a provider, so the encrypted cases need no files. */
    private static SecretProvider literal(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
        return new CallbackSecretProvider(bytes.length, target -> {
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
    }
}
