package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * What this release's provider guard says, and that scopes remember nothing
 * of where they were opened unless asked to. Isolated: the guard's allowance
 * is a system property.
 */
@Isolated
class SecretChangedLinesTest {

    /** The refusal says what the provider reads: a file for file, something for another kind. */
    @Test
    void theGuardSaysWhatTheProviderReads() {
        String allowed = System.getProperty(SecretProviders.PROVIDERS_PROPERTY);
        System.clearProperty(SecretProviders.PROVIDERS_PROPERTY);
        try {
            IllegalArgumentException file = assertThrows(IllegalArgumentException.class,
                    () -> SecretProviders.of(Map.of("provider", "file", "path", "/nowhere")));
            assertTrue(file.getMessage().contains("reads a file of this machine"), file.getMessage());
            IllegalArgumentException socket = assertThrows(IllegalArgumentException.class,
                    () -> SecretProviders.of(Map.of("provider", "unix-socket", "path", "/nowhere")));
            assertTrue(socket.getMessage().contains("reads something of this machine"),
                    socket.getMessage());
        } finally {
            if (allowed != null) {
                System.setProperty(SecretProviders.PROVIDERS_PROPERTY, allowed);
            }
        }
    }

    /** Without -Dseclume.debug.scopes=true an open scope remembers nothing of who opened it. */
    @Test
    void anUntracedScopeRemembersNoOrigin() {
        Assumptions.assumeFalse(SecretScope.tracingOrigins(), "this JVM traces scopes");
        try (SecretScope open = SecretScope.allocate(16)) {
            assertTrue(open.segment().byteSize() >= 16);
            assertFalse(SecretScope.openedAt(100).stream()
                    .anyMatch(o -> o.contains(SecretChangedLinesTest.class.getSimpleName())),
                    SecretScope.openedAt(100).toString());
            assertTrue(SecretScope.openedAt(100).isEmpty(), SecretScope.openedAt(100).toString());
        }
    }
}
