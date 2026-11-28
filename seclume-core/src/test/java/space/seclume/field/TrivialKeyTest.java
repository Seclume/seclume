package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * A key of 32 zero bytes - a file from /dev/zero, an empty vault field - or
 * its Base64 AAAA...= was taken as a key, and everything under it was
 * readable by anybody who tried the obvious. Zeros are refused.
 */
class TrivialKeyTest {

    private static void refused(byte[] given) {
        assertThrows(IllegalArgumentException.class,
                () -> FieldKeys.builder().key(1, FieldEncryptionTest.provider(given)).build());
    }

    @Test
    void zerosAreNoKey() {
        refused(new byte[32]);
        refused("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void aRandomKeyIsTaken() throws Exception {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        try (FieldKeys keys = FieldKeys.builder().key(1, FieldEncryptionTest.provider(key))
                .build()) {
            org.junit.jupiter.api.Assertions.assertNotNull(keys);
        }
    }
}
