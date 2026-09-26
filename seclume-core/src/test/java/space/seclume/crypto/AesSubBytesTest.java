package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * The constant-time S-box against the table generated from the definition,
 * for every one of the 256 inputs, both directions - and the constant-time
 * GF(2^8) helpers against a plain reference.
 */
class AesSubBytesTest {

    @Test
    void theComputedSboxIsTheTableForAllInputs() {
        for (int x = 0; x < 256; x++) {
            assertEquals(AesTables.SBOX[x] & 0xff, AesSubBytes.forwardByte(x), "S(" + x + ")");
            assertEquals(AesTables.INV_SBOX[x] & 0xff, AesSubBytes.inverseByte(x),
                    "S^-1(" + x + ")");
        }
    }

    @Test
    void aWholeWordIsFourIndependentBytes() {
        int word = 0x00_53_ca_ff;
        int expected = (AesTables.SBOX[0x00] & 0xff) << 24 | (AesTables.SBOX[0x53] & 0xff) << 16
                | (AesTables.SBOX[0xca] & 0xff) << 8 | (AesTables.SBOX[0xff] & 0xff);
        assertEquals(expected, AesSubBytes.word(word));
    }

    @Test
    void xtimeAndMultiplyMatchTheSchoolbookDefinition() {
        for (int a = 0; a < 256; a++) {
            int shifted = a << 1;
            assertEquals((shifted & 0x100) != 0 ? (shifted ^ 0x11b) & 0xff : shifted & 0xff,
                    AesTables.xtime(a));
            for (int b = 0; b < 256; b++) {
                assertEquals(reference(a, b), AesTables.multiply(a, b), a + "*" + b);
            }
        }
    }

    private static int reference(int a, int b) {
        int product = 0;
        for (int i = 0; i < 8; i++) {
            if ((b >>> i & 1) != 0) {
                product ^= a << i;
            }
        }
        for (int bit = 14; bit >= 8; bit--) {
            if ((product >>> bit & 1) != 0) {
                product ^= 0x11b << (bit - 8);
            }
        }
        return product;
    }
}
