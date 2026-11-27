package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.secret.SecretProvider;

/**
 * A secret that could not be read - a vault not reachable yet at start, or
 * after a restore - left its lines unmasked for the whole refresh interval,
 * five minutes. While one is missing, the reading is tried again within
 * seconds.
 */
@Timeout(30)
class LogRedactionRetryTest {

    private static final byte[] SECRET = "retried-Pa55word".getBytes(StandardCharsets.UTF_8);

    @Test
    void aMissingSecretIsTriedAgainSoon() throws Exception {
        boolean[] reachable = {false};
        SecretProvider vault = new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                if (!reachable[0]) {
                    throw new IllegalStateException("the vault is not reachable yet");
                }
                MemorySegment.copy(SECRET, 0, target, ValueLayout.JAVA_BYTE, 0, SECRET.length);
                return SECRET.length;
            }

            @Override
            public int maxSecretLength() {
                return 64;
            }
        };
        try (SeclumeLogRedactionAutoConfiguration.LogRedaction redaction =
                     new SeclumeLogRedactionAutoConfiguration.LogRedaction(
                             () -> Map.of("db", vault), Duration.ofMinutes(5), false)) {
            assertFalse(redaction.masker().complete());
            reachable[0] = true;
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(
                    SeclumeLogRedactionAutoConfiguration.LogRedaction.RETRY.toSeconds() + 5);
            while (!redaction.masker().complete() && System.nanoTime() < deadline) {
                Thread.sleep(100);
            }
            assertTrue(redaction.masker().complete(), "not tried again before the interval");
            assertTrue(redaction.masker().mask("x retried-Pa55word").contains("[redacted:db]"));
        }
    }
}
