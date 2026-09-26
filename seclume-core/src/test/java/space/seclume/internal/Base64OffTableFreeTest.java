package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/** The table-free Base64 arithmetic against the RFC 4648 alphabet, every value and every byte. */
class Base64OffTableFreeTest {

    private static final String ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    @Test
    void everySixBitValueAndEveryByte() {
        byte[] alphabet = ALPHABET.getBytes(StandardCharsets.US_ASCII);
        for (int x = 0; x < 64; x++) {
            assertEquals(alphabet[x], Base64Off.character(x), "value " + x);
        }
        for (int c = 0; c < 256; c++) {
            assertEquals(ALPHABET.indexOf((char) c) >= 0 && c < 128 ? ALPHABET.indexOf((char) c) : -1,
                    Base64Off.value(c), "byte " + c);
        }
    }
}
