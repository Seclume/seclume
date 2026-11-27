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

    /**
     * A placeholder taken back is one this process did not hand out: a
     * request still carrying it is refused, and its provider is closed. The
     * registry holds one fewer; a second forget is nothing.
     */
    @Test
    void aForgottenPlaceholderIsRefusedAndItsProviderClosed() throws Exception {
        java.util.concurrent.atomic.AtomicBoolean closed = new java.util.concurrent.atomic.AtomicBoolean();
        SecretProvider closing = new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                return 0;
            }

            @Override
            public int maxSecretLength() {
                return 1;
            }

            @Override
            public void close() {
                closed.set(true);
            }
        };
        String placeholder = CredentialPlaceholders.register(closing);
        int before = CredentialPlaceholders.registered();
        assertTrue(SeclumeSslSocketFactory.forget(placeholder));
        assertEquals(before - 1, CredentialPlaceholders.registered());
        assertTrue(closed.get(), "the provider was not closed");
        org.junit.jupiter.api.Assertions.assertThrows(
                CredentialPlaceholders.PlaceholderRefused.class,
                () -> CredentialPlaceholders.provider(placeholder, "api.example:443", "http"));
        assertFalse(SeclumeSslSocketFactory.forget(placeholder), "forgotten twice");
        assertFalse(SeclumeSslSocketFactory.forget("seclume-cred-not-ours"));
    }

    /** One made per request is said - every WARN_EVERY registrations, not each. */
    @Test
    void manyRegistrationsAreSaid() {
        java.util.List<String> said = new java.util.concurrent.CopyOnWriteArrayList<>();
        java.util.logging.Logger log = java.util.logging.Logger.getLogger(
                CredentialPlaceholders.class.getName());
        java.util.logging.Handler handler = new java.util.logging.Handler() {
            @Override
            public void publish(java.util.logging.LogRecord record) {
                said.add(record.getMessage());
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        log.addHandler(handler);
        java.util.List<String> made = new java.util.ArrayList<>();
        try {
            int toNext = CredentialPlaceholders.WARN_EVERY
                    - CredentialPlaceholders.registered() % CredentialPlaceholders.WARN_EVERY;
            for (int i = 0; i < toNext; i++) {
                made.add(CredentialPlaceholders.register(NOTHING));
            }
            assertEquals(1, said.stream().filter(m -> m.contains("Make it once and keep it"))
                    .count(), said.toString());
        } finally {
            log.removeHandler(handler);
            made.forEach(CredentialPlaceholders::forget);
        }
    }
}
