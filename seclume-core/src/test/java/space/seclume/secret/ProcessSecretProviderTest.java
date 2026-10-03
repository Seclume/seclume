package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import space.seclume.Segments;

@EnabledOnOs({OS.LINUX, OS.MAC})
@Timeout(30)
class ProcessSecretProviderTest {
    @Test
    void helperOutputStillArrivesThroughTheFifo() {
        ProcessSecretProvider provider = new ProcessSecretProvider(
                List.of("/bin/sh", "-c", "printf 'fifo-test-secret\\n'"), 64);
        try (SecretScope scope = SecretScope.fromProvider(provider)) {
            assertEquals("fifo-test-secret", new String(Segments.toBytes(scope.secret()),
                    java.nio.charset.StandardCharsets.US_ASCII));
        }
    }
}
