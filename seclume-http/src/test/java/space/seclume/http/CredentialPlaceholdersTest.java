package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import space.seclume.secret.SecretProvider;

/**
 * Placeholders were a nonce shared by the process and a counter: one seen in
 * a log named every other, and the next one too. Each is sixteen random bytes
 * of its own now.
 */
class CredentialPlaceholdersTest {

    private static final SecretProvider NOTHING = new SecretProvider() {
        @Override
        public int writeSecret(MemorySegment target) {
            return 0;
        }

        @Override
        public int maxSecretLength() {
            return 1;
        }
    };

    @Test
    void aPlaceholderIsSixteenRandomBytes() {
        String placeholder = CredentialPlaceholders.register(NOTHING);
        assertTrue(placeholder.startsWith(CredentialPlaceholders.PREFIX), placeholder);
        String body = placeholder.substring(CredentialPlaceholders.PREFIX.length());
        assertTrue(body.matches("[0-9a-f]{32}"), placeholder);
    }

    @Test
    void noPlaceholderNamesAnother() {
        Set<String> seen = new HashSet<>();
        String first = CredentialPlaceholders.register(NOTHING);
        for (int i = 0; i < 200; i++) {
            String next = CredentialPlaceholders.register(NOTHING);
            assertTrue(seen.add(next));
            // No shared stem with the first one beyond what chance gives.
            String a = first.substring(CredentialPlaceholders.PREFIX.length());
            String b = next.substring(CredentialPlaceholders.PREFIX.length());
            int common = 0;
            while (common < a.length() && a.charAt(common) == b.charAt(common)) {
                common++;
            }
            assertTrue(common < 8, first + " and " + next + " share " + common + " characters");
            assertFalse(b.contains("-"), "a nonce and a counter: " + next);
        }
        assertEquals(200, seen.size());
    }
}
