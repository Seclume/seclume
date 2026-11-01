package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import space.seclume.field.BlindIndex.Transform;
import space.seclume.field.EncryptedColumn.Mode;

/**
 * The edges of field encryption's format and of what a blind index does to a
 * value: the shortest sealed value, a key id that uses every byte of the
 * header, a flags byte nobody wrote, the bounds of a prefix and of the bits
 * for a table, and the characters just outside the digits and the capitals.
 * Written against the mutants PIT left alive in this package.
 */
class FieldFormatEdgesTest {

    private static final byte[] KEY = new byte[32];

    static {
        for (int i = 0; i < KEY.length; i++) {
            KEY[i] = (byte) (0x31 + i);
        }
    }

    private static MemorySegment text(String value) {
        return MemorySegment.ofArray(value.getBytes(StandardCharsets.UTF_8));
    }

    /** A value of field encryption's format, version 1, of {@code length} bytes. */
    private static byte[] formatted(int length) {
        byte[] bytes = new byte[length];
        bytes[0] = EncryptedColumn.VERSION;
        return bytes;
    }

    // ----------------------------------------------------------------- Sealed

    @Test
    void theShortestSealedValueIsTheOverheadAlone() {
        Sealed empty = Sealed.of(formatted(EncryptedColumn.OVERHEAD));
        assertEquals(0, empty.plaintextLength(), "a sealed empty string");
        FieldEncryptionException e = assertThrows(FieldEncryptionException.class,
                () -> Sealed.of(formatted(EncryptedColumn.OVERHEAD - 1)));
        assertEquals("a sealed value is field encryption's format, version 1, at least "
                + EncryptedColumn.OVERHEAD + " bytes - this is " + (EncryptedColumn.OVERHEAD - 1)
                + " bytes starting with 1", e.getMessage());
    }

    @Test
    void aWrongVersionIsNamedAsTheUnsignedByteItIs() {
        for (int version : new int[] {0, 2, 0x7f, 0x80, 0xff}) {
            byte[] bytes = formatted(EncryptedColumn.OVERHEAD + 4);
            bytes[0] = (byte) version;
            FieldEncryptionException e = assertThrows(FieldEncryptionException.class, () -> Sealed.of(bytes));
            assertTrue(e.getMessage().endsWith(" bytes starting with " + version), e.getMessage());
        }
    }

    @Test
    void theKeyIdIsTheFourHeaderBytesBigEndian() {
        byte[] bytes = formatted(EncryptedColumn.OVERHEAD + 3);
        bytes[2] = (byte) 0x81;
        bytes[3] = 0x42;
        bytes[4] = 0x23;
        bytes[5] = 0x04;
        Sealed sealed = Sealed.of(bytes);
        assertEquals(0x81422304, sealed.keyId(), "every byte in its place, the first one's top bit included");
        assertEquals("Sealed[3 bytes, key " + 0x81422304 + "]", sealed.toString());
        for (int at = 2; at <= 5; at++) {
            byte[] one = formatted(EncryptedColumn.OVERHEAD);
            one[at] = 1;
            assertEquals(1 << (8 * (5 - at)), Sealed.of(one).keyId(), "a 1 in header byte " + at);
        }
        byte[] all = formatted(EncryptedColumn.OVERHEAD);
        Arrays.fill(all, 2, 6, (byte) 0xff);
        assertEquals(-1, Sealed.of(all).keyId());
    }

    @Test
    void equalSealedValuesHashAlikeAndTheHashIsTheBytes() {
        try (FieldKeys keys = FieldKeys.builder().key(1, FieldEncryptionTest.provider(KEY)).build()) {
            EncryptedColumn ssn = keys.column("t.ssn", Mode.DETERMINISTIC);
            Sealed one = ssn.seal(text("123-45-6789"));
            Sealed again = ssn.seal(text("123-45-6789"));
            Sealed other = ssn.seal(text("987-65-4321"));
            assertEquals(one, again);
            assertEquals(one.hashCode(), again.hashCode());
            assertEquals(Arrays.hashCode(one.ciphertext()), one.hashCode());
            assertNotEquals(one.hashCode(), other.hashCode());
            assertNotEquals(0, one.hashCode());
        }
    }

    // ------------------------------------------------------- EncryptedColumn

    @Test
    void aFlagsByteNobodyWroteIsNamedAsTheUnsignedByteItIs() {
        try (FieldKeys keys = FieldKeys.builder().key(1, FieldEncryptionTest.provider(KEY)).build()) {
            EncryptedColumn column = keys.column("t.a", Mode.RANDOMIZED);
            byte[] stored = column.encrypt(text("x"));
            for (int flags : new int[] {2, 5, 0x7f, 0x80, 0x81, 0xff}) {
                byte[] changed = stored.clone();
                changed[1] = (byte) flags;
                FieldEncryptionException e = assertThrows(FieldEncryptionException.class,
                        () -> column.decrypt(changed, MemorySegment.ofArray(new byte[8])));
                assertEquals("a value of t.a was encrypted with unknown flags " + flags + ", the column is randomized",
                        e.getMessage());
            }
            byte[] deterministic = keys.column("t.d", Mode.DETERMINISTIC).encrypt(text("x"));
            deterministic[1] = Mode.RANDOMIZED.flag();
            FieldEncryptionException wrongMode = assertThrows(FieldEncryptionException.class,
                    () -> keys.column("t.d", Mode.DETERMINISTIC).decrypt(deterministic, MemorySegment.ofArray(new byte[8])));
            assertEquals("a value of t.d was encrypted randomized, the column is deterministic", wrongMode.getMessage());
        }
    }

    // ------------------------------------------------------- SubjectKeyStore

    @Test
    void theKeyTableIsAPlainIdentifierAndNothingElse() {
        javax.sql.DataSource none = (javax.sql.DataSource) java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {javax.sql.DataSource.class}, (proxy, method, arguments) -> {
                    throw new UnsupportedOperationException("not connected in this test: " + method.getName());
                });
        for (String table : new String[] {"subject_keys", "app.subject_keys", "_k", "K$1", "a.b"}) {
            assertDoesNotThrow(() -> SubjectKeyStore.jdbc(none, table), table);
        }
        for (String table : new String[] {"", "1keys", "keys;drop", "a.b.c", "keys x", "keys-1", ".k"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> SubjectKeyStore.jdbc(none, table), table);
            assertEquals("the key table is a plain SQL identifier, not " + table, e.getMessage());
        }
        IllegalArgumentException missing = assertThrows(IllegalArgumentException.class,
                () -> SubjectKeyStore.jdbc(none, null));
        assertEquals("the key table is a plain SQL identifier, not null", missing.getMessage());
    }

    // ------------------------------------------------------------ BlindIndex

    @Test
    void aPrefixOrSuffixIsOneToSixtyFourCharacters() {
        for (int n : new int[] {1, 2, 63, 64}) {
            assertEquals(n, Transform.prefix(n).length());
            assertDoesNotThrow(() -> new Transform("suffix", n, false));
        }
        for (int n : new int[] {0, -1, 65, Integer.MAX_VALUE}) {
            IllegalArgumentException prefix = assertThrows(IllegalArgumentException.class, () -> Transform.prefix(n));
            assertEquals("prefix takes 1 to 64 characters, not " + n, prefix.getMessage());
            IllegalArgumentException suffix = assertThrows(IllegalArgumentException.class,
                    () -> new Transform("suffix", n, true));
            assertEquals("suffix takes 1 to 64 characters, not " + n, suffix.getMessage());
        }
        for (String kind : new String[] {"exact", "digits"}) {
            assertDoesNotThrow(() -> new Transform(kind, 0, false));
            for (int n : new int[] {1, -1, 64}) {
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                        () -> new Transform(kind, n, false));
                assertEquals(kind + " takes no characters, not " + n, e.getMessage());
            }
        }
        IllegalArgumentException unknown = assertThrows(IllegalArgumentException.class,
                () -> new Transform("soundex", 0, false));
        assertEquals("a transform is exact, digits, prefix or suffix, not soundex", unknown.getMessage());
    }

    @Test
    void theSmallestTableAndCandidateCountGiveOneBit() {
        assertEquals(1, BlindIndex.bitsFor(1, 1), "one row, one candidate: the least there is");
        assertEquals(1, BlindIndex.bitsFor(2, 1));
        assertEquals(1, BlindIndex.bitsFor(3, 1));
        assertEquals(2, BlindIndex.bitsFor(4, 1));
        assertEquals(1, BlindIndex.bitsFor(1, Long.MAX_VALUE));
        for (long[] wrong : new long[][] {{0, 0}, {-1, 1}, {1, -1}, {Long.MIN_VALUE, 1}}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> BlindIndex.bitsFor(wrong[0], wrong[1]));
            assertEquals("rows and candidates are at least 1", e.getMessage());
        }
    }

    private static String transformed(Transform transform, String value) {
        byte[] in = value.getBytes(StandardCharsets.UTF_8);
        MemorySegment out = MemorySegment.ofArray(new byte[Math.max(1, in.length)]);
        int length = BlindIndex.apply(transform, MemorySegment.ofArray(in), out);
        return new String(out.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
    }

    @Test
    void digitsAreZeroToNineAndNothingBesideThem() {
        assertEquals("09", transformed(Transform.DIGITS, "/0:9"), "'/' and ':' sit just outside the digits");
        assertEquals("0123456789", transformed(Transform.DIGITS, "+0 (12) 345-67.89!"));
        assertEquals("", transformed(Transform.DIGITS, "/:"));
        assertEquals("", transformed(Transform.DIGITS, "٠٩"), "Arabic-Indic digits are not ASCII digits");
    }

    @Test
    void caseFoldingIsTheTwentySixCapitalsAndNothingBesideThem() {
        assertEquals("@az[`az{", transformed(Transform.CASE_INSENSITIVE, "@AZ[`az{"),
                "'@' and '[' sit just outside the capitals");
        assertEquals("abcdefghijklmnopqrstuvwxyz", transformed(Transform.CASE_INSENSITIVE,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        assertEquals("Ü", transformed(Transform.CASE_INSENSITIVE, "Ü"), "only ASCII is folded");
        assertEquals("AZ", transformed(Transform.EXACT, "AZ"));
    }

    @Test
    void aSuffixLongerThanTheValueIsTheWholeValue() {
        assertEquals("abc", transformed(new Transform("suffix", 3, false), "abc"));
        assertEquals("abc", transformed(new Transform("suffix", 64, false), "abc"));
        assertEquals("bc", transformed(new Transform("suffix", 2, false), "abc"));
        assertEquals("üc", transformed(new Transform("suffix", 2, false), "aüc"), "counted in characters");
        assertEquals("a", transformed(Transform.prefix(1), "aüc"));
        assertEquals("aü", transformed(Transform.prefix(2), "aüc"));
    }
}
