package space.seclume.logging;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import space.seclume.secret.SecretProvider;

/**
 * The masker dropped the old password's fingerprints at the first refresh
 * after a rotation - while MySQL's RETAIN CURRENT PASSWORD or a rollout in
 * progress kept it good, and it still turned up in lines. It is looked for
 * one refresh longer.
 */
class RotationOverlapTest {

    @Test
    void theOldPasswordIsMaskedOneRefreshLonger() {
        AtomicReference<String> current = new AtomicReference<>("first-password-decoy");
        SecretProvider provider = new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                byte[] bytes = current.get().getBytes(StandardCharsets.US_ASCII);
                MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
                return bytes.length;
            }

            @Override
            public int maxSecretLength() {
                return 64;
            }
        };
        try (SecretMasker masker = new SecretMasker(() -> Map.of("db", provider))) {
            assertFalse(masker.mask("login with first-password-decoy").contains("first-password"));
            current.set("second-password-decoy");
            masker.refresh();
            assertFalse(masker.mask("login with first-password-decoy").contains("first-password"),
                    "the old password, still good, went to the log the moment it was rotated");
            assertFalse(masker.mask("login with second-password-decoy").contains("second-password"));
            masker.refresh();
            assertTrue(masker.mask("login with first-password-decoy").contains("first-password"),
                    "the old one is looked for one refresh, not for ever");
            assertFalse(masker.mask("login with second-password-decoy").contains("second-password"));
        }
    }
}
