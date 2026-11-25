package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.heapdump.OffHeapSecrets;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretUnavailableException;

/**
 * The heap dump endpoint redacts a dump of every secret it is told about. A
 * secret that could not be read was skipped with a warning, and the dump went
 * out as redacted with that secret inside. Now it stops the redaction: a dump
 * not searched for a secret is not passed on as redacted.
 */
@Isolated
class RedactionSecretsTest {

    private static SecretProvider decoy(String value) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
                MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
                return bytes.length;
            }

            @Override
            public int maxSecretLength() {
                return 64;
            }
        };
    }

    private static SecretProvider unreachable() {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                throw new SecretUnavailableException("vault: no route to host (decoy)");
            }

            @Override
            public int maxSecretLength() {
                return 64;
            }
        };
    }

    @Test
    void aSecretThatCannotBeReadStopsTheRedaction() {
        Map<String, SecretProvider> configured = new LinkedHashMap<>();
        configured.put("api", decoy("sk_live_DECOY_redaction_api"));
        configured.put("vault", unreachable());
        RedactionSecrets secrets = new RedactionSecrets(configured);
        IllegalStateException stopped = assertThrows(IllegalStateException.class, secrets::open);
        assertTrue(stopped.getMessage().contains("vault"), stopped.getMessage());
        assertTrue(stopped.getMessage().contains("not passed on as redacted"));
    }

    @Test
    void everySecretReadIsLookedFor() throws Exception {
        Map<String, SecretProvider> configured = new LinkedHashMap<>();
        configured.put("api", decoy("sk_live_DECOY_redaction_api"));
        configured.put("smtp", decoy("DECOY-smtp-password-1"));
        RedactionSecrets secrets = new RedactionSecrets(configured);
        try (OffHeapSecrets.Opened opened = secrets.open()) {
            List<String> labels = opened.needles().stream().map(n -> n.label()).toList();
            assertTrue(labels.containsAll(List.of("api", "smtp")), labels.toString());
        }
    }
}
