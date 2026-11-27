package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.inventory.CryptoInventory;
import space.seclume.secret.SecretScope;

/**
 * Crypto-shredding: a key per subject, wrapped by the ring; shredding one
 * subject leaves every value of theirs unreadable and everyone else's as it
 * was - and a backup of the key store dies with the ring key that wrapped it.
 *
 * <p>Isolated: it counts the inventory's rings.
 */
@Isolated
class SubjectKeysTest {

    private static final byte[] MASTER1 = pattern(1);
    private static final byte[] MASTER2 = pattern(2);

    private static byte[] pattern(int seed) {
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) (seed * 41 + i * 7);
        }
        return key;
    }

    private static FieldKeys ring(int primary, byte[]... keys) {
        FieldKeys.Builder builder = FieldKeys.builder();
        for (int i = 0; i < keys.length; i++) {
            if (keys[i] != null) {
                builder.key(i + 1, FieldEncryptionTest.provider(keys[i]));
            }
        }
        return builder.primary(primary).build();
    }

    private static MemorySegment text(String value) {
        return MemorySegment.ofArray(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String read(EncryptedColumn column, byte[] value) {
        try (SecretScope out = SecretScope.allocate(256)) {
            out.length(column.decrypt(value, out.segment()));
            return new String(out.secret().toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
        }
    }

    /**
     * Two nodes over one store: a subject shredded on one reached the other
     * only when its cached ring fell out of the cache - on a busy subject,
     * never. A cached ring is read again once it is older than its maximum age.
     */
    @Test
    void aShredElsewhereReachesThisNodeWithinTheMaximumAge() throws Exception {
        SubjectKeyStore store = SubjectKeyStore.inMemory();
        try (FieldKeys master = ring(1, MASTER1);
             SubjectKeys here = SubjectKeys.of(master, store);
             SubjectKeys there = SubjectKeys.of(master, store)) {
            java.lang.reflect.Field age = SubjectKeys.class.getDeclaredField("maxAgeNanos");
            age.setAccessible(true);
            age.setLong(here, java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(100));
            byte[] stored = here.column("customer-1", "customer.email", Mode.RANDOMIZED)
                    .encrypt(text("alice@example.org"));
            assertEquals("alice@example.org", read(here.existingColumn("customer-1",
                    "customer.email", Mode.RANDOMIZED), stored));
            assertTrue(there.shred("customer-1"));
            Thread.sleep(200);
            assertThrows(RuntimeException.class, () -> read(here.existingColumn("customer-1",
                    "customer.email", Mode.RANDOMIZED), stored),
                    "the shredded subject was still read here");
        }
    }

    /**
     * Within its age a cached ring is used as it is - the store is not asked
     * on every read. (A shred on this node reaches it at once; one elsewhere,
     * within the age.)
     */
    @Test
    void aCachedRingIsUsedWithinItsAge() throws Exception {
        SubjectKeyStore store = SubjectKeyStore.inMemory();
        try (FieldKeys master = ring(1, MASTER1);
             SubjectKeys here = SubjectKeys.of(master, store);
             SubjectKeys there = SubjectKeys.of(master, store)) {
            byte[] stored = here.column("customer-2", "customer.email", Mode.RANDOMIZED)
                    .encrypt(text("bob@example.org"));
            assertTrue(there.shred("customer-2"));
            assertEquals("bob@example.org", read(here.existingColumn("customer-2",
                    "customer.email", Mode.RANDOMIZED), stored),
                    "a ring within its age was read again from the store");
        }
    }

    /** A ring past its age is read again, and the one it replaces is wiped. */
    @Test
    void aRingReadAgainWipesTheOneItReplaces() throws Exception {
        SubjectKeyStore store = SubjectKeyStore.inMemory();
        try (FieldKeys master = ring(1, MASTER1);
             SubjectKeys here = SubjectKeys.of(master, store)) {
            java.lang.reflect.Field age = SubjectKeys.class.getDeclaredField("maxAgeNanos");
            age.setAccessible(true);
            age.setLong(here, java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(50));
            EncryptedColumn before = here.column("customer-3", "customer.email", Mode.RANDOMIZED);
            byte[] stored = before.encrypt(text("carol@example.org"));
            Thread.sleep(150);
            EncryptedColumn after = here.existingColumn("customer-3", "customer.email",
                    Mode.RANDOMIZED);
            assertEquals("carol@example.org", read(after, stored));
            assertThrows(RuntimeException.class, () -> before.encrypt(text("x")),
                    "the replaced ring still held its key");
        }
    }

    @Test
    void eachSubjectReadsItsOwnAndNoOneElses() {
        try (FieldKeys master = ring(1, MASTER1);
             SubjectKeys subjects = SubjectKeys.of(master, SubjectKeyStore.inMemory())) {
            byte[] alice = subjects.column("customer-1", "customer.email", Mode.RANDOMIZED)
                    .encrypt(text("alice@example.org"));
            byte[] bob = subjects.column("customer-2", "customer.email", Mode.RANDOMIZED)
                    .encrypt(text("bob@example.org"));
            assertEquals("alice@example.org",
                    read(subjects.existingColumn("customer-1", "customer.email", Mode.RANDOMIZED), alice));
            assertEquals("bob@example.org",
                    read(subjects.existingColumn("customer-2", "customer.email", Mode.RANDOMIZED), bob));
            EncryptedColumn bobs = subjects.existingColumn("customer-2", "customer.email", Mode.RANDOMIZED);
            assertThrows(FieldEncryptionException.class, () -> read(bobs, alice),
                    "a value of one subject opened under another's key");
        }
    }

    @Test
    void theSameValueDiffersBetweenSubjectsEvenDeterministically() {
        try (FieldKeys master = ring(1, MASTER1);
             SubjectKeys subjects = SubjectKeys.of(master, SubjectKeyStore.inMemory())) {
            byte[] one = subjects.column("a", "c.ssn", Mode.DETERMINISTIC).encrypt(text("123"));
            byte[] two = subjects.column("b", "c.ssn", Mode.DETERMINISTIC).encrypt(text("123"));
            byte[] oneAgain = subjects.column("a", "c.ssn", Mode.DETERMINISTIC).encrypt(text("123"));
            assertFalse(Arrays.equals(one, two));
            assertArrayEquals(one, oneAgain, "searchable within the subject");
        }
    }

    @Test
    void shreddingMakesEveryValueOfTheSubjectNoiseAndNobodyElses() {
        SubjectKeyStore store = SubjectKeyStore.inMemory();
        try (FieldKeys master = ring(1, MASTER1); SubjectKeys subjects = SubjectKeys.of(master, store)) {
            List<byte[]> alices = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                alices.add(subjects.column("alice", "order.address", Mode.RANDOMIZED)
                        .encrypt(text("street " + i)));
            }
            byte[] bob = subjects.column("bob", "order.address", Mode.RANDOMIZED).encrypt(text("bob's"));
            assertTrue(subjects.exists("alice"));
            assertTrue(subjects.shred("alice"));
            assertFalse(subjects.exists("alice"));
            assertFalse(subjects.shred("alice"), "nothing left the second time");

            FieldEncryptionException refused = assertThrows(FieldEncryptionException.class,
                    () -> subjects.existingColumn("alice", "order.address", Mode.RANDOMIZED));
            assertTrue(refused.getMessage().contains("shredded"), refused.getMessage());
            // Writing for her again makes a new key - which opens none of the old values.
            EncryptedColumn fresh = subjects.column("alice", "order.address", Mode.RANDOMIZED);
            for (byte[] old : alices) {
                assertThrows(FieldEncryptionException.class, () -> read(fresh, old));
            }
            assertEquals("bob's", read(subjects.existingColumn("bob", "order.address", Mode.RANDOMIZED), bob));
        }
    }

    @Test
    void anotherInstanceWithTheSameStoreAndRingReadsTheSame() {
        SubjectKeyStore store = SubjectKeyStore.inMemory();
        byte[] value;
        try (FieldKeys master = ring(1, MASTER1); SubjectKeys first = SubjectKeys.of(master, store)) {
            value = first.column("tenant-9", "doc.title", Mode.RANDOMIZED).encrypt(text("quarterly"));
        }
        try (FieldKeys master = ring(1, MASTER1); SubjectKeys second = SubjectKeys.of(master, store)) {
            assertEquals("quarterly", read(second.existingColumn("tenant-9", "doc.title", Mode.RANDOMIZED), value));
        }
        try (FieldKeys other = ring(1, MASTER2); SubjectKeys wrong = SubjectKeys.of(other, store)) {
            assertThrows(FieldEncryptionException.class,
                    () -> wrong.existingColumn("tenant-9", "doc.title", Mode.RANDOMIZED),
                    "a key store opened with another ring");
        }
    }

    @Test
    void aWrappedKeyIsBoundToItsSubject() {
        SubjectKeyStore store = SubjectKeyStore.inMemory();
        try (FieldKeys master = ring(1, MASTER1); SubjectKeys subjects = SubjectKeys.of(master, store)) {
            subjects.column("alice", "x", Mode.RANDOMIZED);
            byte[] hers = store.load("alice");
            assertEquals(FieldKeys.KEY_LENGTH + EncryptedColumn.OVERHEAD, hers.length,
                    "the key is stored wrapped, never as itself");
            assertTrue(store.insert("mallory", hers));
            assertThrows(FieldEncryptionException.class,
                    () -> subjects.existingColumn("mallory", "x", Mode.RANDOMIZED),
                    "a key copied to another subject's entry opens nothing there");
        }
    }

    /**
     * The backup question, answered: a copy of the key store taken before the
     * shredding opens the subject as long as the ring key that wrapped it
     * exists - and not once the ring has rotated and that key is gone.
     */
    @Test
    void aBackupOfTheKeyStoreDiesWithTheRingKeyThatWrappedIt() {
        SubjectKeyStore store = SubjectKeyStore.inMemory();
        byte[] value;
        byte[] backup;
        try (FieldKeys master = ring(1, MASTER1); SubjectKeys subjects = SubjectKeys.of(master, store)) {
            value = subjects.column("alice", "c.name", Mode.RANDOMIZED).encrypt(text("Alice"));
            backup = store.load("alice");
            subjects.shred("alice");
        }
        SubjectKeyStore restored = SubjectKeyStore.inMemory();
        restored.insert("alice", backup);
        try (FieldKeys master = ring(1, MASTER1); SubjectKeys fromBackup = SubjectKeys.of(master, restored)) {
            assertEquals("Alice", read(fromBackup.existingColumn("alice", "c.name", Mode.RANDOMIZED), value),
                    "the ring key that wrapped it still exists - so the backup still opens her");
        }
        // The ring rotated to key 2, key 1 destroyed: the same backup opens nothing.
        try (FieldKeys rotated = ring(2, null, MASTER2);
             SubjectKeys fromBackup = SubjectKeys.of(rotated, restored)) {
            assertThrows(FieldEncryptionException.class,
                    () -> fromBackup.existingColumn("alice", "c.name", Mode.RANDOMIZED));
        }
    }

    @Test
    void liveKeysAreRewrappedWhenTheRingRotates() {
        SubjectKeyStore store = SubjectKeyStore.inMemory();
        byte[] value;
        try (FieldKeys one = ring(1, MASTER1); SubjectKeys subjects = SubjectKeys.of(one, store)) {
            value = subjects.column("bob", "c.name", Mode.RANDOMIZED).encrypt(text("Bob"));
        }
        try (FieldKeys both = ring(2, MASTER1, MASTER2)) {
            EncryptedColumn wrapping = both.column(SubjectKeys.WRAPPING, Mode.RANDOMIZED);
            byte[] old = store.load("bob");
            byte[] rewrapped = wrapping.reencrypt(old, "bob".getBytes(StandardCharsets.UTF_8));
            assertEquals(2, wrapping.keyId(rewrapped));
            store.delete("bob");
            store.insert("bob", rewrapped);
        }
        try (FieldKeys two = ring(2, null, MASTER2); SubjectKeys subjects = SubjectKeys.of(two, store)) {
            assertEquals("Bob", read(subjects.existingColumn("bob", "c.name", Mode.RANDOMIZED), value),
                    "the subject's own key did not change - only its wrapping");
        }
    }

    @Test
    void theCacheKeepsTheRecentAndWipesTheRest() {
        try (FieldKeys master = ring(1, MASTER1);
             SubjectKeys subjects = SubjectKeys.of(master, SubjectKeyStore.inMemory(), 2)) {
            byte[] a = subjects.column("a", "c", Mode.RANDOMIZED).encrypt(text("A"));
            EncryptedColumn aColumn = subjects.column("a", "c", Mode.RANDOMIZED);
            subjects.column("b", "c", Mode.RANDOMIZED);
            subjects.column("c", "c", Mode.RANDOMIZED);
            // a fell out: its ring was wiped, and the column taken from it refuses.
            assertThrows(RuntimeException.class, () -> read(aColumn, a));
            assertEquals("A", read(subjects.existingColumn("a", "c", Mode.RANDOMIZED), a),
                    "asked again, it is unwrapped again");
            assertTrue(subjects.toString().contains("2 of at most 2"));
        }
    }

    @Test
    void whenTwoWritersMakeAKeyAtOnceTheFirstOneCounts() {
        SubjectKeyStore shared = SubjectKeyStore.inMemory();
        try (FieldKeys master = ring(1, MASTER1)) {
            byte[] theirs;
            try (SubjectKeys other = SubjectKeys.of(master, shared)) {
                other.column("zoe", "c", Mode.RANDOMIZED);
                theirs = shared.load("zoe");
            }
            AtomicInteger loads = new AtomicInteger();
            SubjectKeyStore racing = new SubjectKeyStore() {
                @Override
                public byte[] load(String subject) {
                    // The first look finds nothing - the other writer is not done yet.
                    return loads.getAndIncrement() == 0 ? null : shared.load(subject);
                }

                @Override
                public boolean insert(String subject, byte[] wrapped) {
                    return shared.insert(subject, wrapped);
                }

                @Override
                public boolean delete(String subject) {
                    return shared.delete(subject);
                }
            };
            try (SubjectKeys mine = SubjectKeys.of(master, racing)) {
                byte[] value = mine.column("zoe", "c", Mode.RANDOMIZED).encrypt(text("Z"));
                assertArrayEquals(theirs, shared.load("zoe"), "the first key stays");
                try (SubjectKeys reader = SubjectKeys.of(master, shared)) {
                    assertEquals("Z", read(reader.existingColumn("zoe", "c", Mode.RANDOMIZED), value));
                }
            }
        }
    }

    /**
     * A shred while the subject's key was being read let the reader cache the
     * key just deleted and read on with it - the shredded subject readable
     * again from that instance until it closed.
     */
    @Test
    void aShredDuringAReadLeavesNothingToRead() throws Exception {
        SubjectKeyStore shared = SubjectKeyStore.inMemory();
        try (FieldKeys master = ring(1, MASTER1)) {
            byte[] value;
            try (SubjectKeys writer = SubjectKeys.of(master, shared)) {
                value = writer.column("ann", "c", Mode.RANDOMIZED).encrypt(text("A"));
            }
            java.util.concurrent.CountDownLatch loading = new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.CountDownLatch shredded = new java.util.concurrent.CountDownLatch(1);
            SubjectKeyStore slow = new SubjectKeyStore() {
                @Override
                public byte[] load(String subject) {
                    byte[] wrapped = shared.load(subject);     // read before the shred
                    loading.countDown();
                    try {
                        shredded.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return wrapped;
                }

                @Override
                public boolean insert(String subject, byte[] wrapped) {
                    return shared.insert(subject, wrapped);
                }

                @Override
                public boolean delete(String subject) {
                    return shared.delete(subject);
                }
            };
            try (SubjectKeys subjects = SubjectKeys.of(master, slow)) {
                java.util.concurrent.CompletableFuture<String> reader =
                        java.util.concurrent.CompletableFuture.supplyAsync(() ->
                                read(subjects.existingColumn("ann", "c", Mode.RANDOMIZED), value));
                loading.await();
                subjects.shred("ann");
                shredded.countDown();
                java.util.concurrent.ExecutionException failed = assertThrows(
                        java.util.concurrent.ExecutionException.class,
                        () -> reader.get(10, java.util.concurrent.TimeUnit.SECONDS));
                assertTrue(failed.getCause() instanceof FieldEncryptionException,
                        String.valueOf(failed.getCause()));
            }
            try (SubjectKeys after = SubjectKeys.of(master, shared)) {
                assertThrows(FieldEncryptionException.class,
                        () -> after.existingColumn("ann", "c", Mode.RANDOMIZED));
            }
        }
    }

    @Test
    void subjectRingsDoNotFloodTheInventory() {
        try (FieldKeys master = ring(1, MASTER1);
             SubjectKeys subjects = SubjectKeys.of(master, SubjectKeyStore.inMemory())) {
            long before = dataKeys();
            for (int i = 0; i < 20; i++) {
                subjects.column("s" + i, "c", Mode.RANDOMIZED);
            }
            assertEquals(before, dataKeys());
        }
    }

    private static long dataKeys() {
        return CryptoInventory.snapshot().stream()
                .filter(a -> a.kind() == CryptoInventory.Kind.DATA_KEY).count();
    }

    @Test
    void nonsenseIsRefused() {
        try (FieldKeys master = ring(1, MASTER1)) {
            assertThrows(IllegalArgumentException.class, () -> SubjectKeys.of(null, SubjectKeyStore.inMemory()));
            assertThrows(IllegalArgumentException.class, () -> SubjectKeys.of(master, null));
            assertThrows(IllegalArgumentException.class, () -> SubjectKeys.of(master, SubjectKeyStore.inMemory(), 0));
            SubjectKeys subjects = SubjectKeys.of(master, SubjectKeyStore.inMemory());
            assertThrows(IllegalArgumentException.class, () -> subjects.column("", "c", Mode.RANDOMIZED));
            assertThrows(IllegalArgumentException.class, () -> subjects.column(null, "c", Mode.RANDOMIZED));
            assertThrows(IllegalArgumentException.class, () -> subjects.shred("x".repeat(201)));
            subjects.close();
            assertThrows(IllegalStateException.class, () -> subjects.column("a", "c", Mode.RANDOMIZED));
            assertThrows(IllegalArgumentException.class, () -> SubjectKeyStore.jdbc(null, "t; drop"));
        }
        assertNotEquals(0, MASTER1[1]);
    }

    /**
     * Shredding wipes the subject's ring in memory, not only its key in the
     * store: a column taken before the shred refuses after it - and so do the
     * cached rings when the whole thing closes. Every scope they held is wiped.
     */
    @Test
    void shreddingAndClosingWipeTheRingsInMemory() {
        long before = space.seclume.secret.SecretScope.open();
        try (FieldKeys master = ring(1, MASTER1)) {
            SubjectKeys subjects = SubjectKeys.of(master, SubjectKeyStore.inMemory());
            EncryptedColumn alice = subjects.column("alice", "customer.email", Mode.RANDOMIZED);
            EncryptedColumn bob = subjects.column("bob", "customer.email", Mode.RANDOMIZED);
            byte[] bobs = bob.encrypt(text("bob@example.org"));
            long withBoth = space.seclume.secret.SecretScope.open();
            assertTrue(subjects.shred("alice"));
            assertTrue(space.seclume.secret.SecretScope.open() < withBoth,
                    "the shredded subject's ring is wiped in memory, not only deleted from the store");
            IllegalStateException shredded = assertThrows(IllegalStateException.class,
                    () -> alice.encrypt(text("x")), "the shredded subject's column still worked");
            assertTrue(shredded.getMessage().contains("closed"), shredded.getMessage());
            assertEquals("bob@example.org", read(bob, bobs), "the others are untouched");
            long withBob = space.seclume.secret.SecretScope.open();
            subjects.close();
            assertTrue(space.seclume.secret.SecretScope.open() < withBob, "the cached rings are wiped on close");
            assertThrows(IllegalStateException.class, () -> read(bob, bobs),
                    "a cached ring outlived the close");
        }
        assertEquals(before, space.seclume.secret.SecretScope.open(),
                "nothing of the subjects or the ring is left in memory");
    }

    @Test
    void existsSaysNoForWhoNeverHadAKeyAndChecksTheName() {
        try (FieldKeys master = ring(1, MASTER1);
             SubjectKeys subjects = SubjectKeys.of(master, SubjectKeyStore.inMemory())) {
            assertFalse(subjects.exists("never-written"));
            subjects.column("written", "c", Mode.RANDOMIZED);
            assertTrue(subjects.exists("written"), "cached");
            try (SubjectKeys fresh = SubjectKeys.of(master, SubjectKeyStore.inMemory())) {
                assertFalse(fresh.exists("written"), "another store, another subject");
            }
            for (String wrong : new String[] {null, "", "x".repeat(201)}) {
                assertThrows(IllegalArgumentException.class, () -> subjects.exists(wrong), String.valueOf(wrong));
                assertThrows(IllegalArgumentException.class, () -> subjects.shred(wrong));
                assertThrows(IllegalArgumentException.class, () -> subjects.column(wrong, "c", Mode.RANDOMIZED));
            }
            String longest = "x".repeat(200);
            subjects.column(longest, "c", Mode.RANDOMIZED);
            assertTrue(subjects.exists(longest), "200 characters are a name");
        }
    }

    @Test
    void aCacheOfOneRingIsEnough() {
        try (FieldKeys master = ring(1, MASTER1)) {
            assertThrows(IllegalArgumentException.class, () -> SubjectKeys.of(master, SubjectKeyStore.inMemory(), 0));
            try (SubjectKeys one = SubjectKeys.of(master, SubjectKeyStore.inMemory(), 1)) {
                byte[] a = one.column("a", "c", Mode.RANDOMIZED).encrypt(text("first"));
                one.column("b", "c", Mode.RANDOMIZED);
                assertEquals("first", read(one.existingColumn("a", "c", Mode.RANDOMIZED), a),
                        "a ring that left the cache is made again from its key in the store");
            }
        }
    }

    /**
     * The race the load test below found in CI, made certain: a reader comes
     * between shred()'s forgetting the cached ring and the store's delete,
     * loads the key that is still stored, and caches its ring. Every read
     * after the shred then opened the subject's values again. The store here
     * holds the delete until that reader has cached its ring.
     */
    @Test
    void aRingReadFromTheStoreDuringTheShredIsNotKept() throws Exception {
        SubjectKeyStore memory = SubjectKeyStore.inMemory();
        java.util.concurrent.CountDownLatch deleting = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch readerDone = new java.util.concurrent.CountDownLatch(1);
        SubjectKeyStore holding = new SubjectKeyStore() {
            @Override
            public byte[] load(String subject) {
                return memory.load(subject);
            }

            @Override
            public boolean insert(String subject, byte[] wrapped) {
                return memory.insert(subject, wrapped);
            }

            @Override
            public boolean delete(String subject) {
                deleting.countDown();
                try {
                    readerDone.await(10, java.util.concurrent.TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return memory.delete(subject);
            }
        };
        try (FieldKeys master = ring(1, MASTER1);
             SubjectKeys subjects = SubjectKeys.of(master, holding)) {
            byte[] value = subjects.column("alice", "order.address", Mode.RANDOMIZED)
                    .encrypt(text("street 1"));
            Thread shredder = Thread.ofPlatform().start(() -> subjects.shred("alice"));
            assertTrue(deleting.await(10, java.util.concurrent.TimeUnit.SECONDS));
            // Between the forgetting and the delete: the key is still stored.
            try {
                read(subjects.existingColumn("alice", "order.address", Mode.RANDOMIZED), value);
            } catch (RuntimeException refused) {
                // refused already - as good
            } finally {
                readerDone.countDown();
            }
            shredder.join(10_000);
            assertThrows(RuntimeException.class, () -> read(subjects.existingColumn("alice",
                    "order.address", Mode.RANDOMIZED), value),
                    "a ring read from the store during the shred outlived it");
        }
    }

    /**
     * Under load: eight readers keep opening values written before the shred
     * while it happens. A read that began after shred() returned and still
     * opened a value is the failure - a key kept by a ring in a reader's hands
     * past the shred.
     */
    @Test
    void noReadThatBeginsAfterTheShredOpensAValueWrittenBeforeIt() throws Exception {
        for (int round = 0; round < 10; round++) {
            try (FieldKeys master = ring(1, MASTER1);
                 SubjectKeys subjects = SubjectKeys.of(master, SubjectKeyStore.inMemory())) {
                List<byte[]> before = new ArrayList<>();
                for (int i = 0; i < 16; i++) {
                    before.add(subjects.column("alice", "order.address", Mode.RANDOMIZED)
                            .encrypt(text("street " + i)));
                }
                java.util.concurrent.atomic.AtomicLong shredDone =
                        new java.util.concurrent.atomic.AtomicLong(Long.MAX_VALUE);
                java.util.concurrent.atomic.AtomicReference<String> violation =
                        new java.util.concurrent.atomic.AtomicReference<>();
                java.util.concurrent.atomic.AtomicBoolean stop =
                        new java.util.concurrent.atomic.AtomicBoolean();
                java.util.concurrent.CountDownLatch going = new java.util.concurrent.CountDownLatch(8);
                List<Thread> readers = new ArrayList<>();
                for (int r = 0; r < 8; r++) {
                    int offset = r;
                    readers.add(Thread.ofPlatform().start(() -> {
                        going.countDown();
                        int i = offset;
                        while (!stop.get()) {
                            long began = System.nanoTime();
                            try {
                                read(subjects.existingColumn("alice", "order.address",
                                        Mode.RANDOMIZED), before.get(i++ % before.size()));
                                if (began - shredDone.get() > 0) {
                                    violation.compareAndSet(null, "a read begun "
                                            + (began - shredDone.get()) / 1000 + " us after the "
                                            + "shred opened a value written before it");
                                }
                            } catch (RuntimeException refused) {
                                // after the shred, as it should be
                            }
                        }
                    }));
                }
                going.await();
                Thread.sleep(2);
                assertTrue(subjects.shred("alice"));
                shredDone.set(System.nanoTime());
                Thread.sleep(20);
                stop.set(true);
                for (Thread reader : readers) {
                    reader.join();
                }
                assertNull(violation.get(), violation.get());
            }
        }
    }
}
