package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
}
