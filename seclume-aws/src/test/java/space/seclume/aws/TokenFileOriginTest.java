package space.seclume.aws;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.secret.SecretProviders;

/**
 * A token file named in the URL is a file the URL's writer chose: like
 * provider=file, it is read only where the JVM allows it - refused at once,
 * not at the first fetch. (The test JVMs allow it; here it is taken away.)
 * One from the environment - ECS and EKS set it - is the platform's, and
 * reading it needs no such allowance.
 */
@Isolated
class TokenFileOriginTest {

    @Test
    void aTokenFileTheUrlNamesNeedsTheJvmsAllowance() {
        String allowed = System.getProperty(SecretProviders.PROVIDERS_PROPERTY);
        System.clearProperty(SecretProviders.PROVIDERS_PROPERTY);
        try {
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> CredentialSources.of("container", Map.of(
                            "container-uri", "http://169.254.170.23/v1/credentials",
                            "container-token-file", "/var/run/secrets/token"), null, null));
            assertTrue(refused.getMessage().contains(SecretProviders.PROVIDERS_PROPERTY),
                    refused.getMessage());
            assertThrows(IllegalArgumentException.class,
                    () -> CredentialSources.of("web-identity", Map.of(
                            "role-arn", "arn:aws:iam::123456789012:role/app",
                            "web-identity-token-file", "/var/run/secrets/token"), null,
                            "eu-central-1"));
        } finally {
            if (allowed != null) {
                System.setProperty(SecretProviders.PROVIDERS_PROPERTY, allowed);
            }
        }
    }
}
