package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.secret.SecretScope;

/**
 * The laws of field encryption, checked over thousands of random cases rather
 * than a handful chosen by hand: rings of one to four keys with any of them
 * primary, column names in any script, values from empty to a few kilobytes
 * with the lengths around AES's block boundaries over-represented, contexts
 * or none.
 *
 * <ul>
 * <li>Whatever is encrypted decrypts to itself - in the same ring and in a new
 *     ring built from the same keys.</li>
 * <li>Deterministic: equal in, equal out; unequal in, unequal out.</li>
 * <li>Randomized: never the same ciphertext twice.</li>
 * <li>Another column, another mode or another context does not decrypt it.</li>
 * <li>Re-encryption and every search term decrypt to the same value.</li>
 * <li>A mutated value ends in {@link FieldEncryptionException} and nothing
 *     else, and leaves no plaintext behind.</li>
 * </ul>
 *
 * <p>Seeded: a failure names its round and replays with
 * {@code -Dseclume.field.seed=}. {@code -Dseclume.field.rounds=} runs longer.
 */
class FieldEncryptionPropertyTest {

    private static final int ROUNDS = Integer.getInteger("seclume.field.rounds", 1_500);
    private static final long SEED = Long.getLong("seclume.field.seed", 20261030L);
    private static final String[] NAMES = {"patient.ssn", "tenant.api_token", "t.c",
            "Kunde.Steuer-ID", "顧客.電話", "пациент.снилс", "a", "x".repeat(300)};
    private static final int[] EDGES = {0, 1, 2, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65,
            255, 256, 257, 1023, 1024};

    @Test
    void whateverIsEncryptedDecryptsToItselfAndToNothingElse() {
        Random random = new Random(SEED);
        for (int round = 0; round < ROUNDS; round++) {
            try {
                oneRound(random);
            } catch (AssertionError | RuntimeException e) {
                throw new AssertionError("round " + round + " of seed " + SEED + ": " + e, e);
            }
        }
    }

    private static void oneRound(Random random) {
        List<byte[]> material = new ArrayList<>();
        int count = 1 + random.nextInt(4);
        int[] ids = new int[count];
        int next = 1 + random.nextInt(1000);
        for (int i = 0; i < count; i++) {
            ids[i] = next;
            next += 1 + random.nextInt(Integer.MAX_VALUE / 8);
            byte[] key = new byte[32];
            random.nextBytes(key);
            material.add(key);
        }
        int primary = ids[random.nextInt(count)];
        String name = NAMES[random.nextInt(NAMES.length)];
        Mode mode = Mode.values()[random.nextInt(2)];
        byte[] plain = value(random);
        byte[] context = random.nextInt(3) == 0 ? value(random) : null;

        try (FieldKeys keys = ring(ids, material, primary);
             FieldKeys again = ring(ids, material, primary);
             SecretScope out = SecretScope.allocate(Math.max(1, plain.length) + 64)) {
            EncryptedColumn column = keys.column(name, mode);
            byte[] value = column.encrypt(MemorySegment.ofArray(plain), context);
            assertEquals(plain.length + EncryptedColumn.OVERHEAD, value.length);
            assertEquals(primary, column.keyId(value));
            assertFalse(column.needsReencryption(value));

            assertArrayEquals(plain, decrypt(column, value, context, out));
            assertArrayEquals(plain, decrypt(again.column(name, mode), value, context, out),
                    "a ring built from the same keys does not read it");

            byte[] second = column.encrypt(MemorySegment.ofArray(plain), context);
            if (mode == Mode.DETERMINISTIC) {
                assertArrayEquals(value, second);
                byte[] other = plain.clone();
                if (other.length > 0) {
                    other[random.nextInt(other.length)] ^= (byte) (1 + random.nextInt(255));
                } else {
                    other = new byte[] {0};
                }
                assertFalse(Arrays.equals(value, column.encrypt(MemorySegment.ofArray(other),
                        context)), "two plaintexts with one ciphertext");
            } else {
                assertFalse(Arrays.equals(value, second), "a randomized value repeated");
            }

            refused(keys.column(name + "'", mode), value, context, out, "another column");
            refused(keys.column(name, other(mode)), value, context, out, "the other mode");
            byte[] wrongContext = context == null || context.length == 0 ? new byte[] {1} : null;
            refused(column, value, wrongContext, out, "another context");

            // Every key of the ring encrypts; every value moves to the primary.
            for (int id : ids) {
                if (id != primary) {
                    try (FieldKeys old = ring(new int[] {id}, List.of(material.get(index(ids, id))),
                            id)) {
                        byte[] under = old.column(name, mode).encrypt(MemorySegment.ofArray(plain),
                                context);
                        assertTrue(column.needsReencryption(under));
                        byte[] moved = column.reencrypt(under, context);
                        assertEquals(primary, column.keyId(moved));
                        assertArrayEquals(plain, decrypt(column, moved, context, out));
                        assertArrayEquals(plain, decrypt(column, under, context, out));
                    }
                }
            }
            if (mode == Mode.DETERMINISTIC && context == null) {
                List<byte[]> terms = column.searchTerms(MemorySegment.ofArray(plain));
                assertEquals(count, terms.size());
                assertArrayEquals(value, terms.get(0));
                for (byte[] term : terms) {
                    assertArrayEquals(plain, decrypt(column, term, null, out));
                }
            }

            mutated(random, column, value, context, out);
        }
    }

    /** A handful of mutations per round: flips, cuts, growths, a header from elsewhere. */
    private static void mutated(Random random, EncryptedColumn column, byte[] value,
            byte[] context, SecretScope out) {
        for (int i = 0; i < 4; i++) {
            byte[] mutated = value.clone();
            switch (random.nextInt(4)) {
                case 0 -> mutated[random.nextInt(mutated.length)] ^= (byte) (1 + random.nextInt(255));
                case 1 -> mutated = Arrays.copyOf(mutated, random.nextInt(mutated.length));
                case 2 -> mutated = Arrays.copyOf(mutated, mutated.length + 1 + random.nextInt(16));
                default -> {
                    int a = random.nextInt(mutated.length);
                    int b = random.nextInt(mutated.length);
                    byte swap = mutated[a];
                    mutated[a] = mutated[b];
                    mutated[b] = swap;
                    if (Arrays.equals(mutated, value)) {
                        continue;
                    }
                }
            }
            refused(column, mutated, context, out, "a mutated value");
        }
    }

    private static void refused(EncryptedColumn column, byte[] value, byte[] context,
            SecretScope out, String what) {
        out.segment().fill((byte) 0x5a);
        try {
            column.decrypt(value, context, out.segment());
            fail(what + " decrypted");
        } catch (FieldEncryptionException expected) {
            // said as such
        }
        long left = 0;
        for (long i = 0; i < Math.min(out.segment().byteSize(), value.length); i++) {
            byte b = out.segment().get(ValueLayout.JAVA_BYTE, i);
            left += b != 0 && b != 0x5a ? 1 : 0;
        }
        assertEquals(0, left, what + ": plaintext left in the target");
    }

    @Test
    void aRandomizedColumnNeverRepeatsANonce() {
        try (FieldKeys keys = FieldEncryptionTest.ring(1, new byte[32])) {
            EncryptedColumn column = keys.column("t.c", Mode.RANDOMIZED);
            java.util.Set<String> nonces = new java.util.HashSet<>();
            for (int i = 0; i < 20_000; i++) {
                byte[] value = column.encrypt(MemorySegment.ofArray(new byte[0]));
                assertTrue(nonces.add(java.util.HexFormat.of().formatHex(value, 6, 18)),
                        "a nonce came twice in " + i + " values");
            }
        }
    }

    @Test
    void anythingAtAllEndsInAValueOrAFieldEncryptionException() {
        Random random = new Random(SEED + 1);
        try (FieldKeys keys = FieldEncryptionTest.ring(1, new byte[32]);
             SecretScope out = SecretScope.allocate(512)) {
            EncryptedColumn[] columns = {keys.column("t.c", Mode.RANDOMIZED),
                    keys.column("t.c", Mode.DETERMINISTIC)};
            for (int round = 0; round < ROUNDS * 4; round++) {
                byte[] junk = new byte[random.nextInt(80)];
                random.nextBytes(junk);
                if (junk.length > 6 && random.nextBoolean()) {
                    junk[0] = EncryptedColumn.VERSION;
                    junk[1] = (byte) random.nextInt(2);
                    junk[2] = 0;
                    junk[3] = 0;
                    junk[4] = 0;
                    junk[5] = 1;
                }
                for (EncryptedColumn column : columns) {
                    try {
                        column.decrypt(junk, out.segment());
                        fail("round " + round + ": random bytes decrypted");
                    } catch (FieldEncryptionException expected) {
                        // said as such
                    } catch (RuntimeException e) {
                        throw new AssertionError("round " + round + ": " + e, e);
                    }
                }
            }
        }
    }

    @Test
    void aNullValueIsRefusedNotEncrypted() {
        try (FieldKeys keys = FieldEncryptionTest.ring(1, new byte[32])) {
            assertThrows(IllegalArgumentException.class,
                    () -> keys.column("t.c", Mode.RANDOMIZED).encrypt(null));
            assertThrows(FieldEncryptionException.class, () -> keys.column("t.c", Mode.RANDOMIZED)
                    .plaintextLength(null));
        }
    }

    private static Mode other(Mode mode) {
        return mode == Mode.RANDOMIZED ? Mode.DETERMINISTIC : Mode.RANDOMIZED;
    }

    private static int index(int[] ids, int id) {
        for (int i = 0; i < ids.length; i++) {
            if (ids[i] == id) {
                return i;
            }
        }
        throw new IllegalArgumentException(String.valueOf(id));
    }

    private static byte[] value(Random random) {
        int length = random.nextInt(3) == 0 ? EDGES[random.nextInt(EDGES.length)]
                : random.nextInt(3000);
        byte[] value = new byte[length];
        random.nextBytes(value);
        return value;
    }

    private static FieldKeys ring(int[] ids, List<byte[]> material, int primary) {
        FieldKeys.Builder builder = FieldKeys.builder().primary(primary);
        for (int i = 0; i < ids.length; i++) {
            builder.key(ids[i], FieldEncryptionTest.provider(material.get(i)));
        }
        return builder.build();
    }

    private static byte[] decrypt(EncryptedColumn column, byte[] value, byte[] context,
            SecretScope out) {
        int length = column.decrypt(value, context, out.segment());
        return out.segment().asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
    }
}
