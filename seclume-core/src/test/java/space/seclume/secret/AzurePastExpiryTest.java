package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.time.Instant;

import org.junit.jupiter.api.Test;

/**
 * Key Vault hands a secret out after its exp. Taken as the credential's end,
 * a past exp made the pool see every connection as expired - a new login per
 * borrow. A past exp is no end now; a future one still is.
 */
class AzurePastExpiryTest {

    @Test
    void aPastExpIsNoEndAndAFutureOneIs() {
        assertNull(AzureKeyVaultSecretProvider.stillMeant(Instant.now().minusSeconds(3600), "db"));
        Instant later = Instant.now().plusSeconds(3600);
        assertEquals(later, AzureKeyVaultSecretProvider.stillMeant(later, "db"));
        assertNull(AzureKeyVaultSecretProvider.stillMeant(null, "db"));
    }
}
