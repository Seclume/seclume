package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import space.seclume.field.EncryptedColumn.Context;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.EncryptedColumn.Padding;
import space.seclume.secret.SecretProvider;

/**
 * A ciphertext showed its plaintext's length to the byte: a column of
 * diagnoses told "flu" from "pancreatic carcinoma" by length alone. A column
 * can pad now - to multiples of a size, or to powers of two - and only the
 * padded size shows. Padded and unpadded values are read by every column.
 */
class PaddingTest {

    private static SecretProvider key() {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                for (int i = 0; i < 32; i++) {
                    target.set(ValueLayout.JAVA_BYTE, i, (byte) (11 * i + 3));
                }
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        };
    }

    private static MemorySegment text(String text) {
        return MemorySegment.ofArray(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String read(EncryptedColumn column, byte[] value) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(Math.max(1, column.plaintextLength(value)));
            int length = column.decrypt(value, target);
            return new String(target.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.UTF_8);
        }
    }

    @Test
    void valuesOfOnePaddedSizeLookAlike() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key()).build()) {
            EncryptedColumn column = keys.column("patients.diagnosis", Mode.RANDOMIZED,
                    Context.OPTIONAL, Padding.toMultipleOf(32));
            Set<Integer> lengths = new HashSet<>();
            for (String diagnosis : new String[] {"", "flu", "fracture", "pancreatic carcin"}) {
                byte[] value = column.encrypt(text(diagnosis));
                lengths.add(value.length);
                assertEquals(diagnosis, read(column, value));
            }
            assertEquals(Set.of(EncryptedColumn.OVERHEAD + 32), lengths,
                    "every value up to 28 bytes is one padded size");
            assertEquals(EncryptedColumn.OVERHEAD + 64,
                    column.encrypt(text("x".repeat(29))).length);
        }
    }

    @Test
    void powersOfTwoShowTheOrderOfMagnitude() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key()).build()) {
            EncryptedColumn column = keys.column("notes.body", Mode.RANDOMIZED, Context.OPTIONAL,
                    Padding.toPowerOfTwo(16));
            assertEquals(EncryptedColumn.OVERHEAD + 16, column.encrypt(text("a")).length);
            assertEquals(EncryptedColumn.OVERHEAD + 32, column.encrypt(text("a".repeat(13))).length);
            assertEquals(EncryptedColumn.OVERHEAD + 1024,
                    column.encrypt(text("a".repeat(600))).length);
            assertEquals("a".repeat(600), read(column, column.encrypt(text("a".repeat(600)))));
        }
    }

    /** Switching padding on needs no migration; rotation finds what to rewrite. */
    @Test
    void paddedAndUnpaddedValuesAreReadByEveryColumn() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key()).build()) {
            EncryptedColumn plain = keys.column("users.ssn", Mode.DETERMINISTIC);
            EncryptedColumn padded = keys.column("users.ssn", Mode.DETERMINISTIC, Context.OPTIONAL,
                    Padding.toMultipleOf(16));
            byte[] old = plain.encrypt(text("123-45-6789"));
            byte[] fresh = padded.encrypt(text("123-45-6789"));
            assertEquals("123-45-6789", read(padded, old));
            assertEquals("123-45-6789", read(plain, fresh));
            assertTrue(padded.needsReencryption(old), "an unpadded value in a padding column");
            assertFalse(padded.needsReencryption(fresh));
            assertFalse(plain.needsReencryption(fresh), "padding is never taken off");
            assertArrayEquals(fresh, padded.reencrypt(old), "deterministic: the same padded value");
            assertArrayEquals(fresh, padded.searchTerms(text("123-45-6789")).get(0),
                    "a search finds the padded value");
        }
    }

    /** The flag is authenticated: a value whose padding bit is flipped does not open. */
    @Test
    void thePaddingFlagCannotBeFlipped() {
        try (FieldKeys keys = FieldKeys.builder().key(1, key()).build()) {
            EncryptedColumn column = keys.column("t.c", Mode.RANDOMIZED, Context.OPTIONAL,
                    Padding.toMultipleOf(16));
            byte[] value = column.encrypt(text("secret"));
            value[1] ^= EncryptedColumn.PADDED;
            assertThrows(FieldEncryptionException.class, () -> read(column, value));
        }
    }

    @Test
    void sizesOutOfRangeAreRefused() {
        assertThrows(IllegalArgumentException.class, () -> Padding.toMultipleOf(1));
        assertThrows(IllegalArgumentException.class, () -> Padding.toMultipleOf(65537));
        assertThrows(IllegalArgumentException.class, () -> Padding.toPowerOfTwo(0));
    }
}
