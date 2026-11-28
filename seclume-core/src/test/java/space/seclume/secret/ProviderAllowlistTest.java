package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * Settings come from JDBC URLs and Properties, and whoever writes a URL also
 * picks the host the secret goes to: {@code provider=file&path=/etc/...} had
 * the machine read any file it could and send it there as the password. The
 * providers that read something of this machine are chosen from settings only
 * where the JVM names them in {@code -Dseclume.secret.providers}.
 */
// Alone: the system property is the whole JVM's.
@Isolated
class ProviderAllowlistTest {

    @TempDir
    Path directory;

    @Test
    void aProviderWithALocalResourceNeedsToBeNamed() {
        for (String kind : new String[] {"file", "env-file", "envfile", "unix-socket", "process",
                "dpapi", "credential-manager", "libsecret", "secret-service", "keychain",
                "shamir", "spiffe-jwt"}) {
            assertFalse(SecretProviders.chosenFromSettings(kind, null), kind);
            assertFalse(SecretProviders.chosenFromSettings(kind, ""), kind);
            assertFalse(SecretProviders.chosenFromSettings(kind, "vault"), kind);
        }
        assertTrue(SecretProviders.chosenFromSettings("file", "file"));
        assertTrue(SecretProviders.chosenFromSettings("envfile", "env-file"), "by its alias");
        assertTrue(SecretProviders.chosenFromSettings("env-file", " envfile , file "));
        assertTrue(SecretProviders.chosenFromSettings("secret-service", "libsecret"));
        assertFalse(SecretProviders.chosenFromSettings("file", "files"));
    }

    @Test
    void aRemoteProviderIsChosenAsBefore() {
        for (String kind : new String[] {"vault", "vault-transit", "aws-secrets-manager",
                "azure-key-vault", "gcp-secret-manager", "kms-decrypt", "rds-iam", "encrypted",
                "gcp-metadata", "azure-managed-identity", "none"}) {
            assertTrue(SecretProviders.chosenFromSettings(kind, null), kind);
        }
    }

    @Test
    void withoutThePropertyAFileFromTheUrlIsRefused() throws Exception {
        Path secret = Files.writeString(directory.resolve("secret"), "s3cret-for-the-test");
        String before = System.getProperty(SecretProviders.PROVIDERS_PROPERTY);
        System.clearProperty(SecretProviders.PROVIDERS_PROPERTY);
        try {
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> SecretProviders.of(Map.of("provider", "file",
                            "path", secret.toString())));
            assertTrue(refused.getMessage().contains("-Dseclume.secret.providers=file"),
                    refused.getMessage());

            System.setProperty(SecretProviders.PROVIDERS_PROPERTY, "file");
            SecretProvider allowed = SecretProviders.of(Map.of("provider", "file",
                    "path", secret.toString()));
            assertEquals(FileSecretProvider.class, allowed.getClass());
        } finally {
            if (before == null) {
                System.clearProperty(SecretProviders.PROVIDERS_PROPERTY);
            } else {
                System.setProperty(SecretProviders.PROVIDERS_PROPERTY, before);
            }
        }
    }

    @Test
    void aFileNestedInAnotherProviderIsCheckedToo() {
        String before = System.getProperty(SecretProviders.PROVIDERS_PROPERTY);
        System.clearProperty(SecretProviders.PROVIDERS_PROPERTY);
        try {
            // encrypted is no local resource itself; its key, read from a file, is.
            assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(Map.of(
                    "provider", "encrypted", "cipher-provider", "file", "cipher-path", "/x",
                    "key-provider", "file", "key-path", "/y")));
        } finally {
            if (before != null) {
                System.setProperty(SecretProviders.PROVIDERS_PROPERTY, before);
            }
        }
    }
}
