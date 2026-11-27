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
