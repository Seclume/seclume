package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.Checkpoint;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * Field keys across a checkpoint. A ring held its data keys - and every
 * column's and index's keys derived from them - for as long as it was open:
 * a CRaC or SnapStart image of a running application held them all, and
 * {@code seclume-crac}, which waits for no secret to be open, refused the
 * checkpoint over them. Now a checkpoint wipes them, and the next use reads
 * the keys again from their providers.
 */
@Isolated
class FieldKeysCheckpointTest {

    /** A 32-byte key from native memory; counts reads and closes; can be made to fail. */
    private static final class Key implements SecretProvider {
        final byte seed;
        final AtomicInteger reads = new AtomicInteger();
        final AtomicInteger closes = new AtomicInteger();
        final AtomicBoolean failing = new AtomicBoolean();

        Key(int seed) {
            this.seed = (byte) seed;
        }

        @Override
        public int writeSecret(MemorySegment target) {
            if (failing.get()) {
                throw new IllegalStateException("the key source is not there");
            }
            reads.incrementAndGet();
            for (int i = 0; i < 32; i++) {
                target.set(ValueLayout.JAVA_BYTE, i, (byte) (seed * 31 + i * 7 + 1));
            }
            return 32;
        }

        @Override
        public int maxSecretLength() {
            return 64;
        }

        @Override
        public void close() {
            closes.incrementAndGet();
        }
    }

    private static MemorySegment text(Arena arena, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        MemorySegment segment = arena.allocate(bytes.length);
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    private static String decrypt(EncryptedColumn column, byte[] value) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(value.length);
            int length = column.decrypt(value, out);
            return new String(out.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.UTF_8);
        }
    }

    @Test
    void aCheckpointWipesEveryKeyAndTheNextUseReadsThemAgain() {
        Key one = new Key(1);
        Key two = new Key(2);
        Checkpoint.wipeAll();                    // what other tests left cached
        long before = SecretScope.open();
        try (FieldKeys keys = FieldKeys.builder().key(1, one).key(2, two).build();
             Arena arena = Arena.ofConfined()) {
            EncryptedColumn random = keys.column("customer.iban", EncryptedColumn.Mode.RANDOMIZED);
            EncryptedColumn exact = keys.column("customer.email",
                    EncryptedColumn.Mode.DETERMINISTIC);
            BlindIndex index = keys.blindIndex("customer.email", 16, BlindIndex.Transform.EXACT);
            byte[] iban = random.encrypt(text(arena, "DE89 3704 0044 0532 0130 00"));
            byte[] email = exact.encrypt(text(arena, "ada@example.com"));
            long term = index.term(text(arena, "ada@example.com"));
            assertTrue(SecretScope.open() > before, "the ring's keys are open secrets");
            assertEquals(1, one.reads.get());

            Checkpoint.wipeAll();
            assertEquals(before, SecretScope.open(),
                    "a key is still open: it would be in the checkpoint image");
            assertEquals(0, one.closes.get(), "the providers stay the ring's");

            // After the restore: everything works as before, from keys read again.
            assertEquals("DE89 3704 0044 0532 0130 00", decrypt(random, iban));
            assertEquals(2, one.reads.get());
            assertEquals(2, two.reads.get());
            assertArrayEquals(email, exact.encrypt(text(arena, "ada@example.com")),
                    "a deterministic column encrypts as it did");
            assertEquals(term, index.term(text(arena, "ada@example.com")));
            assertEquals("ada@example.com", decrypt(exact, email));
            // A column made after the checkpoint too.
            EncryptedColumn later = keys.column("customer.phone", EncryptedColumn.Mode.RANDOMIZED);
            assertEquals("+49 30 1234", decrypt(later, later.encrypt(text(arena, "+49 30 1234"))));

            // Wiped twice in a row, read once.
            Checkpoint.wipeAll();
            Checkpoint.wipeAll();
            assertEquals("ada@example.com", decrypt(exact, email));
            assertEquals(3, one.reads.get());
        }
        assertEquals(1, one.closes.get(), "the providers are closed with the ring");
        assertEquals(1, two.closes.get());
        assertEquals(before, SecretScope.open());
    }

    @Test
    void aKeySourceThatIsGoneAfterTheRestoreFailsTheUseAndTheNextOneTriesAgain() {
        Key one = new Key(3);
        Checkpoint.wipeAll();                    // what other tests left cached
        long before = SecretScope.open();
        try (FieldKeys keys = FieldKeys.builder().key(1, one).build();
             Arena arena = Arena.ofConfined()) {
            EncryptedColumn column = keys.column("t.c", EncryptedColumn.Mode.RANDOMIZED);
            byte[] value = column.encrypt(text(arena, "secret value"));
            Checkpoint.wipeAll();
            one.failing.set(true);
            assertThrows(IllegalStateException.class, () -> decrypt(column, value));
            assertEquals(before, SecretScope.open(), "a failed reload leaves nothing open");
            one.failing.set(false);
            assertEquals("secret value", decrypt(column, value));
        }
    }

    @Test
    void usesAcrossCheckpointsGetTheirKeysEveryTime() throws Exception {
        Key one = new Key(4);
        try (FieldKeys keys = FieldKeys.builder().key(1, one).build()) {
            EncryptedColumn column = keys.column("t.c", EncryptedColumn.Mode.RANDOMIZED);
            AtomicBoolean stop = new AtomicBoolean();
            List<Throwable> failures = java.util.Collections.synchronizedList(new ArrayList<>());
            List<Thread> workers = new ArrayList<>();
            for (int t = 0; t < 4; t++) {
                int n = t;
                workers.add(Thread.ofPlatform().start(() -> {
                    try (Arena arena = Arena.ofConfined()) {
                        for (int i = 0; i < 300; i++) {
                            String plain = "value " + n + "-" + i;
                            assertEquals(plain, decrypt(column, column.encrypt(text(arena,
                                    plain))));
                        }
                    } catch (Throwable e) {
                        failures.add(e);
                    }
                }));
            }
            Thread checkpoints = Thread.ofPlatform().start(() -> {
                while (!stop.get()) {
                    Checkpoint.wipeAll();
                    Thread.onSpinWait();
                }
            });
            for (Thread worker : workers) {
                worker.join();
            }
            stop.set(true);
            checkpoints.join();
            assertEquals(List.of(), failures);
            assertTrue(one.reads.get() >= 1);
        }
    }

    @Test
    void aSubjectsRingIsDroppedAndMadeAgainFromTheStore() {
        Key wrapping = new Key(5);
        SubjectKeyStore store = SubjectKeyStore.inMemory();
        Checkpoint.wipeAll();                    // what other tests left cached
        long before = SecretScope.open();
        try (FieldKeys ring = FieldKeys.builder().key(1, wrapping).build();
             SubjectKeys subjects = SubjectKeys.of(ring, store);
             Arena arena = Arena.ofConfined()) {
            byte[] value = subjects.column("customer-7", "notes", EncryptedColumn.Mode.RANDOMIZED)
                    .encrypt(text(arena, "private notes"));
            Checkpoint.wipeAll();
            assertEquals(before, SecretScope.open(), "a subject's key is still open");
            assertEquals("private notes", decrypt(subjects.existingColumn("customer-7", "notes",
                    EncryptedColumn.Mode.RANDOMIZED), value));
        }
    }
}
