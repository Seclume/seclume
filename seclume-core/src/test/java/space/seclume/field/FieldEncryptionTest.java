package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;

import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * Field encryption without a database: the format, the keys, the modes, the
 * rotation and every way a value is refused. The database tests
 * ({@code LocalEncryptedColumnTest} in each driver) show the same through
 * JDBC, and that the server holds nothing but ciphertext.
 *
 * <p>Isolated: two tests count the open {@link SecretScope}s, which every
 * other class changes too.
 */
@org.junit.jupiter.api.parallel.Isolated
class FieldEncryptionTest {

    private static final HexFormat HEX = HexFormat.of();
    /** 00 01 02 ... 1f: the key of the vectors below. */
    private static final byte[] KEY = new byte[32];

    static {
        for (int i = 0; i < 32; i++) {
            KEY[i] = (byte) i;
        }
    }

    // ----------------------------------------------------------------- format

    /**
     * The format pinned against an implementation written separately, in
     * Python with {@code cryptography}'s HKDF and AES-GCM-SIV: what one
     * writes, the other reads. A change here breaks every stored value.
     */
    @Test
    void theFormatIsTheOneAnotherImplementationWrites() {
        try (FieldKeys keys = ring(1, KEY)) {
            EncryptedColumn ssn = keys.column("patient.ssn", Mode.DETERMINISTIC);
            assertEquals("01010000000100000000000000000000000056f4639a25ffbcbb64a3f553771d7b18"
                    + "c80019d978e4804e0bc35d", HEX.formatHex(ssn.encrypt(text("123-45-6789"))));
            assertEquals("01010000000100000000000000000000000053d999a2d40fe015822b823b899c74cc",
                    HEX.formatHex(ssn.encrypt(MemorySegment.ofArray(new byte[0]))));
        }
        try (FieldKeys keys = ring(7, KEY)) {
            EncryptedColumn token = keys.column("tenant.api_token", Mode.RANDOMIZED);
            byte[] written = HEX.parseHex("010000000007101112131415161718191a1b2197c548a93057f2c4"
                    + "3aca6cbec96de5748bed5c0e9eee095be206");
            try (SecretScope back = SecretScope.allocate(64)) {
                back.length(token.decrypt(written, "row-7".getBytes(StandardCharsets.US_ASCII),
                        back.segment()));
                assertEquals("tök-ĸ€y", new String(back.secret().toArray(ValueLayout.JAVA_BYTE),
                        StandardCharsets.UTF_8));
            }
        }
    }

    @Test
    void randomizedValuesDifferEveryTimeAndDecrypt() {
        try (FieldKeys keys = ring(1, KEY)) {
            EncryptedColumn column = keys.column("t.c", Mode.RANDOMIZED);
            byte[] first = column.encrypt(text("the same"));
            byte[] second = column.encrypt(text("the same"));
            assertFalse(Arrays.equals(first, second), "a randomized column repeated itself");
            assertEquals(8 + EncryptedColumn.OVERHEAD, first.length);
            assertEquals("the same", decrypt(column, first));
            assertEquals("the same", decrypt(column, second));
            assertEquals(8, column.plaintextLength(first));
            assertEquals(1, column.keyId(first));
        }
    }

    @Test
    void deterministicValuesAreEqualForEqualPlaintextOnly() {
        try (FieldKeys keys = ring(1, KEY)) {
            EncryptedColumn column = keys.column("t.c", Mode.DETERMINISTIC);
            assertArrayEquals(column.encrypt(text("a")), column.encrypt(text("a")));
            assertFalse(Arrays.equals(column.encrypt(text("a")), column.encrypt(text("b"))));
        }
    }

    @Test
    void theSameValueIsAnotherCiphertextInAnotherColumnOrMode() {
        try (FieldKeys keys = ring(1, KEY)) {
            byte[] a = keys.column("t.a", Mode.DETERMINISTIC).encrypt(text("x"));
            byte[] b = keys.column("t.b", Mode.DETERMINISTIC).encrypt(text("x"));
            assertNotEquals(HEX.formatHex(a), HEX.formatHex(b));
            // Copied into another column of the same mode: does not authenticate there.
            FieldEncryptionException copied = assertThrows(FieldEncryptionException.class,
                    () -> decrypt(keys.column("t.b", Mode.DETERMINISTIC), a));
            assertTrue(copied.getMessage().contains("did not authenticate"), copied.getMessage());
            // Into a column of the other mode: refused by its flags, before any key is used.
            FieldEncryptionException mode = assertThrows(FieldEncryptionException.class,
                    () -> decrypt(keys.column("t.a", Mode.RANDOMIZED), a));
            assertTrue(mode.getMessage().contains("deterministically"), mode.getMessage());
        }
    }

    @Test
    void aContextBindsTheValueToItsRow() {
        try (FieldKeys keys = ring(1, KEY);
             SecretScope out = SecretScope.allocate(16)) {
            EncryptedColumn column = keys.column("t.c", Mode.RANDOMIZED);
            byte[] row7 = column.encrypt(text("secret"), bytes("7"));
            assertEquals(6, column.decrypt(row7, bytes("7"), out.segment()));
            assertThrows(FieldEncryptionException.class,
                    () -> column.decrypt(row7, bytes("8"), out.segment()));
            assertThrows(FieldEncryptionException.class,
                    () -> column.decrypt(row7, out.segment()));
            assertArrayEquals(new byte[16], out.segment().toArray(ValueLayout.JAVA_BYTE),
                    "a value that did not authenticate left plaintext behind");
        }
    }

    @Test
    void everyAlteredByteIsRefused() {
        try (FieldKeys keys = ring(1, KEY);
             SecretScope out = SecretScope.allocate(64)) {
            for (Mode mode : Mode.values()) {
                EncryptedColumn column = keys.column("t.c", mode);
                byte[] value = column.encrypt(text("a value worth forging"));
                for (int at = 0; at < value.length; at++) {
                    for (int bit = 0; bit < 8; bit++) {
                        byte[] altered = value.clone();
                        altered[at] ^= (byte) (1 << bit);
                        int position = at;
                        assertThrows(FieldEncryptionException.class,
                                () -> column.decrypt(altered, out.segment()),
                                mode + ": bit " + bit + " of byte " + position);
                    }
                }
                for (int cut = 0; cut < value.length; cut++) {
                    byte[] shorter = Arrays.copyOf(value, cut);
                    assertThrows(FieldEncryptionException.class,
                            () -> column.decrypt(shorter, out.segment()));
                }
            }
        }
    }

    @Test
    void whatIsNotThisFormatSaysSo() {
        try (FieldKeys keys = ring(1, KEY);
             SecretScope out = SecretScope.allocate(64)) {
            EncryptedColumn column = keys.column("t.c", Mode.RANDOMIZED);
            byte[] plain = "an old, unencrypted value of this column".getBytes(
                    StandardCharsets.US_ASCII);
            FieldEncryptionException e = assertThrows(FieldEncryptionException.class,
                    () -> column.decrypt(plain, out.segment()));
            assertTrue(e.getMessage().contains("not in seclume's field encryption format"),
                    e.getMessage());
            byte[] value = column.encrypt(text("x"));
            value[1] = 4;
            e = assertThrows(FieldEncryptionException.class,
                    () -> column.decrypt(value, out.segment()));
            assertTrue(e.getMessage().contains("unknown flags"), e.getMessage());
        }
    }

    @Test
    void aTargetTooSmallIsRefusedNotFilled() {
        try (FieldKeys keys = ring(1, KEY);
             Arena arena = Arena.ofConfined()) {
            EncryptedColumn column = keys.column("t.c", Mode.RANDOMIZED);
            byte[] value = column.encrypt(text("twelve bytes"));
            MemorySegment small = arena.allocate(11);
            assertThrows(FieldEncryptionException.class, () -> column.decrypt(value, small));
            assertArrayEquals(new byte[11], small.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    // --------------------------------------------------------------- rotation

    @Test
    void aNewPrimaryKeyReadsTheOldValuesAndMovesThemOver() {
        byte[] key2 = KEY.clone();
        key2[0] = 99;
        byte[] oldRandom;
        byte[] oldSearchable;
        try (FieldKeys before = ring(1, KEY)) {
            oldRandom = before.column("t.r", Mode.RANDOMIZED).encrypt(text("r"));
            oldSearchable = before.column("t.d", Mode.DETERMINISTIC).encrypt(text("d"));
        }
        try (FieldKeys during = FieldKeys.builder().key(1, provider(KEY)).key(2, provider(key2))
                .build()) {
            assertEquals(2, during.primary(), "the highest number, when none is named");
            EncryptedColumn random = during.column("t.r", Mode.RANDOMIZED);
            EncryptedColumn searchable = during.column("t.d", Mode.DETERMINISTIC);
            assertTrue(random.needsReencryption(oldRandom));
            assertEquals("r", decrypt(random, oldRandom));

            List<byte[]> terms = searchable.searchTerms(text("d"));
            assertEquals(2, terms.size());
            assertEquals(2, searchable.keyId(terms.get(0)), "the primary key first");
            assertArrayEquals(oldSearchable, terms.get(1), "the old key's ciphertext finds the old row");

            byte[] moved = random.reencrypt(oldRandom);
            assertEquals(2, random.keyId(moved));
            assertFalse(random.needsReencryption(moved));
            assertSame(moved, random.reencrypt(moved), "a value under the primary key stays");
            byte[] movedSearchable = searchable.reencrypt(oldSearchable);
            assertArrayEquals(terms.get(0), movedSearchable);

            try (FieldKeys after = ring(2, key2)) {
                assertEquals("r", decrypt(after.column("t.r", Mode.RANDOMIZED), moved));
                FieldEncryptionException gone = assertThrows(FieldEncryptionException.class,
                        () -> decrypt(after.column("t.r", Mode.RANDOMIZED), oldRandom));
                assertTrue(gone.getMessage().contains("under key 1"), gone.getMessage());
            }
        }
    }

    @Test
    void anOlderPrimaryCanBeNamed() {
        try (FieldKeys keys = FieldKeys.builder().key(1, provider(KEY))
                .key(2, provider(new byte[32])).primary(1).build()) {
            assertEquals(1, keys.column("t.c", Mode.RANDOMIZED).keyId(
                    keys.column("t.c", Mode.RANDOMIZED).encrypt(text("x"))));
        }
    }

    @Test
    void aRandomizedColumnHasNoSearchTerms() {
        try (FieldKeys keys = ring(1, KEY)) {
            assertThrows(IllegalStateException.class,
                    () -> keys.column("t.c", Mode.RANDOMIZED).searchTerms(text("x")));
        }
    }

    // ------------------------------------------------------------------- keys

    @Test
    void aKeyIsThirtyTwoBytesOrTheirBase64() {
        byte[] base64 = (java.util.Base64.getEncoder().encodeToString(KEY) + "\n")
                .getBytes(StandardCharsets.US_ASCII);
        byte[] expected;
        try (FieldKeys raw = ring(1, KEY)) {
            expected = raw.column("t.c", Mode.DETERMINISTIC).encrypt(text("x"));
        }
        try (FieldKeys encoded = ring(1, base64)) {
            assertArrayEquals(expected, encoded.column("t.c", Mode.DETERMINISTIC)
                    .encrypt(text("x")), "the Base64 of a key is that key");
        }
        assertThrows(IllegalArgumentException.class, () -> ring(1, new byte[16]));
        assertThrows(IllegalArgumentException.class, () -> ring(1,
                java.util.Base64.getEncoder().encode(new byte[24])),
                "the 32 characters of 24 bytes' Base64 are text, not a 32-byte key");
        assertThrows(IllegalArgumentException.class, () -> ring(1,
                "this is not base64 at all, is it?!".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void theRingIsCheckedWhenBuilt() {
        assertThrows(IllegalArgumentException.class, () -> FieldKeys.builder().build());
        assertThrows(IllegalArgumentException.class, () -> FieldKeys.builder().key(0, provider(KEY)));
        assertThrows(IllegalArgumentException.class,
                () -> FieldKeys.builder().key(1, provider(KEY)).key(1, provider(KEY)));
        assertThrows(IllegalArgumentException.class,
                () -> FieldKeys.builder().key(1, provider(KEY)).primary(2).build());
    }

    @Test
    void aKeyThatCannotBeReadLeavesNoOtherKeyBehind() {
        long open = SecretScope.open();
        assertThrows(IllegalArgumentException.class, () -> FieldKeys.builder()
                .key(1, provider(KEY)).key(2, provider(new byte[5])).build());
        assertEquals(open, SecretScope.open(), "key 1 stayed in memory after key 2 failed");
    }

    @Test
    void closingWipesTheKeysAndStopsTheColumns() {
        long open = SecretScope.open();
        FieldKeys keys = ring(1, KEY);
        EncryptedColumn column = keys.column("t.c", Mode.RANDOMIZED);
        byte[] value = column.encrypt(text("x"));
        assertTrue(SecretScope.open() > open);
        keys.close();
        assertEquals(open, SecretScope.open(), "a key is still in memory after close");
        assertThrows(IllegalStateException.class, () -> column.encrypt(text("x")));
        try (SecretScope out = SecretScope.allocate(8)) {
            assertThrows(IllegalStateException.class, () -> column.decrypt(value, out.segment()));
        }
        assertThrows(IllegalStateException.class, () -> keys.column("t.c", Mode.RANDOMIZED));
        keys.close();
    }

    @Test
    void columnsAreSharedAndUsableFromManyThreads() throws Exception {
        try (FieldKeys keys = ring(1, KEY)) {
            assertSame(keys.column("t.c", Mode.RANDOMIZED), keys.column("t.c", Mode.RANDOMIZED));
            ExecutorService pool = Executors.newFixedThreadPool(8);
            try {
                List<Future<String>> results = new ArrayList<>();
                for (int i = 0; i < 64; i++) {
                    String value = "value " + i;
                    results.add(pool.submit(() -> {
                        EncryptedColumn column = keys.column("t.c", Mode.RANDOMIZED);
                        return decrypt(column, column.encrypt(text(value)));
                    }));
                }
                for (int i = 0; i < 64; i++) {
                    assertEquals("value " + i, results.get(i).get());
                }
            } finally {
                pool.shutdownNow();
            }
        }
    }

    @Test
    void theNameOfAColumnIsRequired() {
        try (FieldKeys keys = ring(1, KEY)) {
            assertThrows(IllegalArgumentException.class, () -> keys.column(" ", Mode.RANDOMIZED));
            assertThrows(IllegalArgumentException.class, () -> keys.column("t.c", null));
            assertFalse(keys.toString().contains("00"), keys.toString());
        }
    }

    // ----------------------------------------------------------------- sealed

    @Test
    void aSealedValueOpensIntoNativeMemoryAndSaysNothingAboutItself() {
        try (FieldKeys keys = ring(3, KEY);
             SecretScope out = SecretScope.allocate(32)) {
            EncryptedColumn token = keys.column("t.token", Mode.RANDOMIZED);
            Sealed sealed = token.seal(text("ghp_secret"), bytes("row-1"));
            assertEquals(10, sealed.plaintextLength());
            assertEquals(3, sealed.keyId());
            assertFalse(sealed.deterministic());
            assertEquals("Sealed[10 bytes, key 3]", sealed.toString());
            assertEquals(10, token.open(sealed, bytes("row-1"), out.segment()));
            assertThrows(FieldEncryptionException.class,
                    () -> token.open(sealed, out.segment()), "without its context");
            assertThrows(IllegalArgumentException.class, () -> token.open(null, out.segment()));
            assertEquals(null, token.seal(null));
            byte[] copy = sealed.ciphertext();
            copy[10] ^= 1;
            assertArrayEquals(sealed.ciphertext(), Sealed.of(sealed.ciphertext()).ciphertext(),
                    "a sealed value changed with the copy handed out");
            assertNotEquals(sealed, Sealed.of(copy));
        }
    }

    @Test
    void deterministicSealedValuesAreEqualForEqualPlaintexts() {
        try (FieldKeys keys = FieldKeys.builder().key(1, provider(KEY))
                .key(2, provider(new byte[32])).primary(2).build()) {
            EncryptedColumn ssn = keys.column("t.ssn", Mode.DETERMINISTIC);
            assertEquals(ssn.seal(text("1")), ssn.seal(text("1")));
            assertEquals(ssn.seal(text("1")).hashCode(), ssn.seal(text("1")).hashCode());
            assertNotEquals(ssn.seal(text("1")), ssn.seal(text("2")));
            assertTrue(ssn.seal(text("1")).deterministic());
            List<Sealed> terms = ssn.searchSealed(text("1"));
            assertEquals(List.of(2, 1), terms.stream().map(Sealed::keyId).toList());
        }
    }

    @Test
    void whatIsNotASealedValueIsRefused() {
        assertEquals(null, Sealed.of(null));
        assertThrows(FieldEncryptionException.class, () -> Sealed.of(new byte[0]));
        assertThrows(FieldEncryptionException.class, () -> Sealed.of(new byte[33]));
        byte[] wrongVersion = new byte[40];
        wrongVersion[0] = 2;
        assertThrows(FieldEncryptionException.class, () -> Sealed.of(wrongVersion));
    }

    @Test
    void theInstalledRingIsTheOneInstalledUntilItCloses() {
        assertThrows(IllegalStateException.class, FieldKeys::installed);
        FieldKeys keys = ring(1, KEY);
        try {
            FieldKeys.install(keys);
            assertSame(keys, FieldKeys.installed());
            FieldKeys.install(null);
            assertThrows(IllegalStateException.class, FieldKeys::installed);
            FieldKeys.install(keys);
        } finally {
            keys.close();
        }
        assertThrows(IllegalStateException.class, FieldKeys::installed,
                "a closed ring stayed installed");
        assertThrows(IllegalStateException.class, () -> FieldKeys.install(keys));
    }

    // ---------------------------------------------------------------- helpers

    static FieldKeys ring(int id, byte[] key) {
        return FieldKeys.builder().key(id, provider(key)).build();
    }

    /** A key handed over from the test - which holds it on its heap, as a test may. */
    static SecretProvider provider(byte[] key) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                MemorySegment.copy(key, 0, target, ValueLayout.JAVA_BYTE, 0, key.length);
                return key.length;
            }

            @Override
            public int maxSecretLength() {
                return Math.max(1, key.length);
            }
        };
    }

    private static MemorySegment text(String value) {
        return MemorySegment.ofArray(value.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static String decrypt(EncryptedColumn column, byte[] value) {
        try (SecretScope out = SecretScope.allocate(Math.max(1, value.length))) {
            out.length(column.decrypt(value, out.segment()));
            return new String(out.secret().toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
        }
    }
}
