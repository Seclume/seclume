package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.internal.Platform;

/**
 * The desktop keyrings as providers: configured from settings, refused
 * without what finds the item, and - where the platform has no such keyring -
 * a clear refusal at read time rather than a crash. The libsecret read itself
 * runs against a real Secret Service in a container (gnome-keyring, items
 * stored with secret-tool); the Keychain has no Mac to run on yet.
 */
class DesktopKeyringTest {

    @Test
    void bothAreConfiguredFromSettings() {
        assertInstanceOf(LibsecretSecretProvider.class, SecretProviders.of(Map.of(
                "provider", "libsecret", "attribute.service", "orders-db",
                "attribute.account", "app")));
        assertInstanceOf(KeychainSecretProvider.class, SecretProviders.of(Map.of(
                "provider", "keychain", "service", "orders-db", "account", "app")));
    }

    @Test
    void whatFindsTheItemIsRequired() {
        assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(Map.of("provider", "libsecret")));
        assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(Map.of("provider", "keychain", "account", "app")));
    }

    @Test
    void anotherPlatformIsToldSo() {
        try (Arena arena = Arena.ofConfined()) {
            if (!Platform.isMac()) {
                SecretUnavailableException refused = assertThrows(
                        SecretUnavailableException.class, () -> new KeychainSecretProvider(
                                "orders-db", "app", 64).writeSecret(arena.allocate(64)));
                assertTrue(refused.getMessage().contains("not available"), refused.getMessage());
            }
            if (!LibsecretSecretProvider.available()) {
                SecretUnavailableException refused = assertThrows(
                        SecretUnavailableException.class, () -> new LibsecretSecretProvider(
                                Map.of("service", "orders-db"), 64).writeSecret(
                                        arena.allocate(64)));
                assertTrue(refused.getMessage().contains("libsecret"), refused.getMessage());
            }
        }
    }
}
