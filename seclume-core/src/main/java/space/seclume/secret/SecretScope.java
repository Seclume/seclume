package space.seclume.secret;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.concurrent.atomic.AtomicLong;

import space.seclume.internal.MemoryLock;

/**
 * The only way to get a segment a secret may live in.
 *
 * <p>It wraps the three things every piece of protocol code would otherwise
 * have to get right on its own, and would eventually forget: allocation in a
 * {@link Arena#ofConfined() confined arena}, pinning the page in RAM, and - the
 * actual point - <b>zeroing before release</b>. Released native memory is
 * reused by the allocator, not erased; without the zeroing the password would
 * still be sitting somewhere in the process.
 *
 * <p>A scope belongs to exactly one thread (confined arena) and lives as
 * briefly as possible - typically for the duration of a handshake:
 *
 * {@snippet :
 * try (SecretScope scope = SecretScope.fromProvider(provider)) {
 *     handshake(scope.secret());
 * }
 * }
 */
public final class SecretScope implements AutoCloseable {

    /**
     * How many secret segments this JVM has allocated. The integrated
     * authentication test uses it to check that the SSPI/Kerberos path touches
     * no secret at all - there the counter has to stay put.
     */
    private static final AtomicLong ALLOCATIONS = new AtomicLong();

    private final Arena arena;
    private final boolean ownsArena;
    private final MemorySegment segment;
    private final boolean locked;
    private int length;
    private boolean closed;

    private SecretScope(Arena arena, boolean ownsArena, int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        this.arena = arena;
        this.ownsArena = ownsArena;
        this.segment = arena.allocate(capacity);
        this.locked = MemoryLock.lock(segment);
        this.length = 0;
        ALLOCATIONS.incrementAndGet();
    }

    /** An empty segment of the requested size in an arena of its own. */
    public static SecretScope allocate(int capacity) {
        return new SecretScope(Arena.ofConfined(), true, capacity);
    }

    /**
     * Like {@link #allocate}, but in an arena someone else owns. Closing then
     * only zeroes - the memory is released when that arena closes.
     *
     * <p>Meant for callers that already have an arena for the handshake, and
     * for the zeroing proof in the tests: there the segment has to stay
     * readable after closing, so that it can be shown to really be zero.
     */
    public static SecretScope in(Arena arena, int capacity) {
        return new SecretScope(arena, false, capacity);
    }

    /**
     * Allocates according to {@link SecretProvider#maxSecretLength()} and lets
     * the provider write into it. If the provider fails, the segment is zeroed
     * and released before the exception travels on.
     */
    public static SecretScope fromProvider(SecretProvider provider) {
        SecretScope scope = allocate(provider.maxSecretLength());
        try {
            int written = provider.writeSecret(scope.segment);
            if (written < 0 || written > scope.segment.byteSize()) {
                throw new SecretUnavailableException(
                        "provider reported an implausible secret length: " + written);
            }
            scope.length = written;
            return scope;
        } catch (RuntimeException e) {
            scope.close();
            throw e;
        }
    }

    /** The whole segment - as large as was requested on allocation. */
    public MemorySegment segment() {
        checkOpen();
        return segment;
    }

    /** Only the part that was written; this is the secret itself. */
    public MemorySegment secret() {
        checkOpen();
        return segment.asSlice(0, length);
    }

    /** Length of the secret in bytes. */
    public int length() {
        checkOpen();
        return length;
    }

    /** Sets the length when your own code writes rather than the provider. */
    public void length(int written) {
        checkOpen();
        if (written < 0 || written > segment.byteSize()) {
            throw new IllegalArgumentException("length outside of the segment");
        }
        this.length = written;
    }

    /** Whether the page is pinned in RAM - for diagnostics and tests. */
    public boolean isLocked() {
        return locked;
    }

    /** How many secret segments this JVM has allocated so far. */
    public static long allocations() {
        return ALLOCATIONS.get();
    }

    /**
     * Zeroes the segment and releases it. Closing more than once is allowed,
     * so that {@code try}-with-resources and an error path do not get in each
     * Gehege kommen.
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        segment.fill((byte) 0);
        if (locked) {
            MemoryLock.unlock(segment);
        }
        if (ownsArena) {
            arena.close();
        }
    }

    /** No {@code toString} with content - it would end up in the log. */
    @Override
    public String toString() {
        return "SecretScope[capacity=" + (closed ? "released" : segment.byteSize())
                + ", locked=" + locked + "]";
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("secret scope is closed");
        }
    }
}
