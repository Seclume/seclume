package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import space.seclume.field.EncryptedColumn.Padding;

/** The ends of padding's range, and a length that is already a power of two. */
class PaddingBoundsTest {

    @Test
    void bothEndsOfTheRangeAreTakenAndOneBeyondIsRefused() {
        assertDoesNotThrow(() -> Padding.toMultipleOf(2));
        assertDoesNotThrow(() -> Padding.toMultipleOf(65536));
        assertThrows(IllegalArgumentException.class, () -> Padding.toMultipleOf(1));
        assertThrows(IllegalArgumentException.class, () -> Padding.toMultipleOf(65537));
        assertDoesNotThrow(() -> Padding.toPowerOfTwo(2));
        assertDoesNotThrow(() -> Padding.toPowerOfTwo(65536));
        assertThrows(IllegalArgumentException.class, () -> Padding.toPowerOfTwo(1));
        assertThrows(IllegalArgumentException.class, () -> Padding.toPowerOfTwo(65537));
    }

    /** A padding's part of its column's identity: what it pads to, and how. */
    @Test
    void eachPaddingNamesItselfApart() {
        assertEquals("none", Padding.NONE.code());
        assertEquals("pow2:16", Padding.toPowerOfTwo(16).code());
        assertEquals("mul:16", Padding.toMultipleOf(16).code());
    }

    /**
     * Padded values of every length round a block's edge come back as they
     * were - one that fills its block to the byte, an empty one in a block no
     * larger than the length prefix - and fit a target of exactly their length.
     */
    @Test
    void paddedValuesAtTheEdgesOfTheirBlockComeBackExactly() {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i * 7 + 3);
        }
        try (FieldKeys ring = FieldKeys.builder().key(1, FieldEncryptionTest.provider(key)).build()) {
            for (Padding padding : new Padding[] {Padding.toMultipleOf(2), Padding.toMultipleOf(4),
                    Padding.toMultipleOf(16), Padding.toPowerOfTwo(16)}) {
                EncryptedColumn column = ring.column("t.c", EncryptedColumn.Mode.RANDOMIZED,
                        EncryptedColumn.Context.OPTIONAL, padding);
                for (int length = 0; length <= 40; length++) {
                    byte[] value = new byte[length];
                    for (int i = 0; i < length; i++) {
                        value[i] = (byte) (i + 1);
                    }
                    byte[] stored = column.encrypt(java.lang.foreign.MemorySegment.ofArray(value));
                    // At most what the padded block holds: the block less the length prefix.
                    assertEquals(padding.paddedLength(EncryptedColumn.LENGTH_PREFIX + length)
                            - EncryptedColumn.LENGTH_PREFIX, column.plaintextLength(stored),
                            padding + " " + length);
                    java.lang.foreign.MemorySegment exact =
                            java.lang.foreign.MemorySegment.ofArray(new byte[length]);
                    assertEquals(length, column.decrypt(stored, exact), padding + " " + length);
                    org.junit.jupiter.api.Assertions.assertArrayEquals(value,
                            exact.toArray(java.lang.foreign.ValueLayout.JAVA_BYTE),
                            padding + " " + length);
                }
            }
        }
    }

    @Test
    void aLengthThatIsAlreadyAPowerOfTwoStaysAsItIs() {
        Padding padding = Padding.toPowerOfTwo(16);
        assertEquals(16, padding.paddedLength(1));
        assertEquals(16, padding.paddedLength(16));
        assertEquals(32, padding.paddedLength(17));
        assertEquals(64, padding.paddedLength(64));
        Padding multiples = Padding.toMultipleOf(16);
        assertEquals(16, multiples.paddedLength(16));
        assertEquals(32, multiples.paddedLength(17));
    }
}
