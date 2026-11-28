package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.junit.jupiter.api.Test;

/**
 * verify=false on Vault, transit, a KMS or a cloud metadata service sent the
 * token and the secret to whoever answered, wherever the host was. Off this
 * machine it takes a system property now, which no URL can set.
 */
class UnverifiedSecretSourceTest {

    @Test
    void anUncheckedServerElsewhereIsRefused() {
        IOException refused = assertThrows(IOException.class,
                () -> SecretFetch.unverifiedOnlyWhereAllowed("vault.example.org", false));
        assertTrue(refused.getMessage().contains("allowUnverifiedSecretSources"));
        assertThrows(IOException.class,
                () -> SecretFetch.unverifiedOnlyWhereAllowed("10.0.0.5", false));
    }

    @Test
    void thisMachineAndACheckedServerPass() {
        assertDoesNotThrow(() -> SecretFetch.unverifiedOnlyWhereAllowed("127.0.0.1", false));
        assertDoesNotThrow(() -> SecretFetch.unverifiedOnlyWhereAllowed("localhost", false));
        assertDoesNotThrow(() -> SecretFetch.unverifiedOnlyWhereAllowed("[::1]", false));
        assertDoesNotThrow(() -> SecretFetch.unverifiedOnlyWhereAllowed("vault.example.org",
                true));
    }
}
