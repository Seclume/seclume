package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * {@link SecretScope} against a model of it: random sequences of what code
 * does with a secret - allocate one, in an arena of its own or someone
 * else's, let a provider fill one (and fail in four ways), write into it,
 * set its length, read it, close it once or twice, from two threads at once,
 * from the wrong thread - and after each step the scope has to agree with the
 * model.
 *
 * <ul>
 * <li>An open scope gives back exactly what was written, as long as was set.</li>
 * <li>A closed one gives back nothing: every accessor refuses it, and its
 *     memory is either zero (an arena someone else owns, which is still
 *     there to be read) or no longer readable at all (its own arena, freed -
 *     a read of it fails, it does not see freed memory).</li>
 * <li>A provider that fails leaves no scope open and its memory freed.</li>
 * <li>A capacity that is none, a length outside the segment, a close from a
 *     thread that may not touch the memory: refused, and nothing changes.</li>
 * <li>{@link SecretScope#open()} is the model's count of open scopes after
 *     every step - so two closes at once count once - and back where it
 *     started at the end.</li>
 * </ul>
 *
 * <p>Seeded: a failure names its round and step and replays with
 * {@code -Dseclume.scope.seed=}. {@code -Dseclume.scope.rounds=} runs longer.
 * {@code @Isolated}: the open count is the process's.
 */
@Isolated
@Timeout(300)
class SecretScopeModelTest {

    private static final int ROUNDS = Integer.getInteger("seclume.scope.rounds", 300);
    private static final int STEPS = 40;
    private static final long SEED = Long.getLong("seclume.scope.seed", 0x5EC5C09EL);

    /** One scope and what the model says it holds. */
    private static final class Modelled {
        final SecretScope scope;
        final MemorySegment raw;
        final boolean ownArena;
        final byte[] content;
        int length;
        boolean closed;

        Modelled(SecretScope scope, boolean ownArena, byte[] content, int length) {
            this.scope = scope;
            this.raw = scope.segment();
            this.ownArena = ownArena;
            this.content = content;
            this.length = length;
        }
    }

    @Test
    void theScopeFollowsTheModel() throws Exception {
        Random random = new Random(SEED);
        long start = SecretScope.open();
        for (int round = 0; round < ROUNDS; round++) {
            List<Modelled> scopes = new ArrayList<>();
            try (Arena shared = Arena.ofShared()) {
                int step = 0;
                try {
                    for (; step < STEPS; step++) {
                        step(random, scopes, shared);
                        long live = scopes.stream().filter(m -> !m.closed).count();
                        assertEquals(start + live, SecretScope.open(), "open scopes");
                    }
                    for (Modelled m : scopes) {
                        close(m);
                    }
                    assertEquals(start, SecretScope.open(), "a scope was left open");
                } catch (AssertionError | Exception e) {
                    for (Modelled m : scopes) {
                        m.scope.close();
                    }
                    throw new AssertionError("round " + round + " step " + step + " of seed "
                            + SEED + ": " + e, e);
                }
            }
        }
    }

    private static void step(Random random, List<Modelled> scopes, Arena shared) throws Exception {
        List<Modelled> open = scopes.stream().filter(m -> !m.closed).toList();
        int choice = open.isEmpty() || scopes.size() < 2 ? random.nextInt(3) : random.nextInt(11);
        switch (choice) {
            case 0 -> allocate(random, scopes, shared);
            case 1 -> fromProvider(random, scopes);
            case 2 -> refusedCapacity(random);
            case 3 -> write(random, open.get(random.nextInt(open.size())));
            case 4 -> length(random, open.get(random.nextInt(open.size())));
            case 5, 6 -> read(open.get(random.nextInt(open.size())));
            case 7 -> close(open.get(random.nextInt(open.size())));
            case 8 -> closeTwiceAtOnce(open.get(random.nextInt(open.size())));
            case 9 -> wrongThread(random);
            default -> {
                Modelled closed = scopes.get(random.nextInt(scopes.size()));
                if (closed.closed) {
                    assertClosed(closed);
                    closed.scope.close();
                }
            }
        }
    }

    private static int capacity(Random random) {
        return switch (random.nextInt(4)) {
            case 0 -> 1 + random.nextInt(16);
            case 1 -> 4095 + random.nextInt(3);
            default -> 1 + random.nextInt(600);
        };
    }

    private static void allocate(Random random, List<Modelled> scopes, Arena shared) {
        int capacity = capacity(random);
        boolean own = random.nextBoolean();
        SecretScope scope = own
                ? (random.nextBoolean() ? SecretScope.allocate(capacity)
                        : SecretScope.allocateShared(capacity))
                : SecretScope.in(shared, capacity);
        assertEquals(capacity, scope.segment().byteSize());
        assertEquals(0, scope.length(), "a new scope holds nothing");
        // Fresh native memory is zero; the model starts there.
        Modelled m = new Modelled(scope, own, new byte[capacity], 0);
        assertArrayEquals(m.content, scope.segment().toArray(ValueLayout.JAVA_BYTE));
        scopes.add(m);
    }

    /**
     * A provider that writes, and then returns its length - or one of four
     * failures: a RuntimeException, an Error, a length below zero, a length
     * beyond what it said it would write.
     */
    private static void fromProvider(Random random, List<Modelled> scopes) {
        int capacity = capacity(random);
        byte[] written = new byte[random.nextInt(capacity + 1)];
        random.nextBytes(written);
        int failure = random.nextInt(6);
        AtomicReference<MemorySegment> target = new AtomicReference<>();
        SecretProvider provider = new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment into) {
                target.set(into);
                MemorySegment.copy(written, 0, into, ValueLayout.JAVA_BYTE, 0, written.length);
                return switch (failure) {
                    case 0 -> throw new SecretUnavailableException("the source failed half-way");
                    case 1 -> throw new StackOverflowError("an error half-way");
                    case 2 -> -1 - random.nextInt(5);
                    case 3 -> capacity + 1 + random.nextInt(5);
                    default -> written.length;
                };
            }

            @Override
            public int maxSecretLength() {
                return capacity;
            }
        };
        long before = SecretScope.open();
        if (failure < 4) {
            Throwable thrown = assertThrows(Throwable.class, () -> SecretScope.fromProvider(provider));
            assertTrue(thrown instanceof SecretUnavailableException
                    || thrown instanceof StackOverflowError, thrown.toString());
            assertEquals(before, SecretScope.open(), "a failed provider left its scope open");
            assertFreed(target.get());
            return;
        }
        SecretScope scope = SecretScope.fromProvider(provider);
        byte[] content = Arrays.copyOf(written, capacity);
        Modelled m = new Modelled(scope, true, content, written.length);
        assertArrayEquals(written, scope.secret().toArray(ValueLayout.JAVA_BYTE));
        scopes.add(m);
    }

    private static void refusedCapacity(Random random) {
        long before = SecretScope.open();
        int capacity = -random.nextInt(3);
        assertThrows(IllegalArgumentException.class, () -> SecretScope.allocate(capacity));
        try (Arena arena = Arena.ofConfined()) {
            assertThrows(IllegalArgumentException.class, () -> SecretScope.in(arena, capacity));
        }
        assertEquals(before, SecretScope.open());
    }

    private static void write(Random random, Modelled m) {
        int capacity = m.content.length;
        int offset = random.nextInt(capacity);
        byte[] bytes = new byte[1 + random.nextInt(capacity - offset)];
        random.nextBytes(bytes);
        MemorySegment.copy(bytes, 0, m.scope.segment(), ValueLayout.JAVA_BYTE, offset, bytes.length);
        System.arraycopy(bytes, 0, m.content, offset, bytes.length);
        // A write past the end is the segment's to refuse, not the scope's.
        assertThrows(IndexOutOfBoundsException.class,
                () -> m.scope.segment().set(ValueLayout.JAVA_BYTE, capacity, (byte) 1));
    }

    private static void length(Random random, Modelled m) {
        int capacity = m.content.length;
        if (random.nextBoolean()) {
            int length = random.nextInt(capacity + 1);
            m.scope.length(length);
            m.length = length;
        } else {
            int outside = random.nextBoolean() ? capacity + 1 + random.nextInt(9) : -1 - random.nextInt(9);
            assertThrows(IllegalArgumentException.class, () -> m.scope.length(outside));
        }
        assertEquals(m.length, m.scope.length());
    }

    private static void read(Modelled m) {
        assertEquals(m.length, m.scope.length());
        assertArrayEquals(Arrays.copyOf(m.content, m.length),
                m.scope.secret().toArray(ValueLayout.JAVA_BYTE));
        assertArrayEquals(m.content, m.scope.segment().toArray(ValueLayout.JAVA_BYTE));
        assertFalse(m.scope.toString().contains("released"));
    }

    private static void close(Modelled m) {
        m.scope.close();
        m.closed = true;
        assertClosed(m);
    }

    /** Two threads close it at the same moment; the count goes down by one. */
    private static void closeTwiceAtOnce(Modelled m) throws Exception {
        CyclicBarrier together = new CyclicBarrier(2);
        List<Throwable> failures = java.util.Collections.synchronizedList(new ArrayList<>());
        Runnable closer = () -> {
            try {
                together.await();
                m.scope.close();
            } catch (Throwable e) {
                failures.add(e);
            }
        };
        Thread one = Thread.ofPlatform().start(closer);
        Thread two = Thread.ofPlatform().start(closer);
        one.join();
        two.join();
        assertEquals(List.of(), failures);
        m.closed = true;
        assertClosed(m);
    }

    /**
     * A scope in a confined arena, closed by a thread that may not touch the
     * memory: refused, still open, still holding the secret - and the owner
     * can then close it.
     */
    private static void wrongThread(Random random) throws Exception {
        try (Arena confined = Arena.ofConfined()) {
            int capacity = capacity(random);
            SecretScope scope = SecretScope.in(confined, capacity);
            byte[] bytes = new byte[capacity];
            random.nextBytes(bytes);
            MemorySegment.copy(bytes, 0, scope.segment(), ValueLayout.JAVA_BYTE, 0, capacity);
            scope.length(capacity);
            AtomicReference<Throwable> refused = new AtomicReference<>();
            Thread other = Thread.ofPlatform().start(() -> {
                try {
                    scope.close();
                } catch (Throwable e) {
                    refused.set(e);
                }
            });
            other.join();
            assertTrue(refused.get() instanceof WrongThreadException, String.valueOf(refused.get()));
            assertArrayEquals(bytes, scope.secret().toArray(ValueLayout.JAVA_BYTE),
                    "the refused close changed the secret");
            MemorySegment raw = scope.segment();
            scope.close();
            assertThrows(IllegalStateException.class, scope::secret);
            assertArrayEquals(new byte[capacity], raw.toArray(ValueLayout.JAVA_BYTE),
                    "the owner's close did not zero it");
        }
    }

    private static void assertClosed(Modelled m) {
        assertThrows(IllegalStateException.class, m.scope::segment);
        assertThrows(IllegalStateException.class, m.scope::secret);
        assertThrows(IllegalStateException.class, m.scope::length);
        assertThrows(IllegalStateException.class, () -> m.scope.length(0));
        assertTrue(m.scope.toString().contains("released"), m.scope.toString());
        if (m.ownArena) {
            assertFreed(m.raw);
        } else {
            assertArrayEquals(new byte[m.content.length], m.raw.toArray(ValueLayout.JAVA_BYTE),
                    "closed, and not zero");
        }
    }

    /** Freed memory cannot be read: the read fails rather than seeing what is there now. */
    private static void assertFreed(MemorySegment segment) {
        assertFalse(segment.scope().isAlive(), "its arena is still open");
        assertThrows(IllegalStateException.class, () -> segment.get(ValueLayout.JAVA_BYTE, 0));
    }
}
