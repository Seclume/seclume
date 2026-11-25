package space.seclume.logging;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretUnavailableException;

/**
 * A refresh whose provider fails - Vault restarting, a file being replaced -
 * dropped that secret from the masker until the next refresh, and log lines
 * carried it unmasked in between. What was looked for stays looked for, and a
 * masker that never read a secret asks to be refreshed early.
 */
class SecretMaskerRefreshTest {

    private static final String SECRET = "sk_live_DECOY_masker_refresh";

    private static SecretProvider flaky(AtomicBoolean down) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                if (down.get()) {
                    throw new SecretUnavailableException("vault is restarting (decoy)");
                }
                byte[] bytes = SECRET.getBytes(StandardCharsets.US_ASCII);
                MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
                return bytes.length;
            }

            @Override
            public int maxSecretLength() {
                return 64;
            }
        };
    }

    @Test
    void aFailedRefreshKeepsWhatWasLookedFor() {
        AtomicBoolean down = new AtomicBoolean();
        try (SecretMasker masker = new SecretMasker(Map.of("api", flaky(down)))) {
            masker.refresh();
            assertFalse(masker.mask("token " + SECRET).contains(SECRET), "the control");
            down.set(true);
            masker.refresh();
            assertFalse(masker.mask("token " + SECRET).contains(SECRET),
                    "the secret went unmasked after a refresh that could not read it");
            assertTrue(masker.complete(), "something earlier is kept: nothing to hurry");
        }
    }

    @Test
    void aFailedRefreshAsksForAnEarlyRetry() {
        AtomicBoolean down = new AtomicBoolean(true);
        try (SecretMasker masker = new SecretMasker(Map.of("api", flaky(down)))) {
            masker.refresh();
            assertFalse(masker.complete(), "nothing is looked for, and nobody is told to retry");
            down.set(false);
            masker.refresh();
            assertTrue(masker.complete());
            assertFalse(masker.mask("token " + SECRET).contains(SECRET));
        }
    }
}
