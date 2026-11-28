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

    /** A hundred logins with the same past exp: one warning - and another once the exp changes. */
    @Test
    void aPastExpIsSaidOncePerSecretAndExpiry() {
        java.util.List<String> said = new java.util.concurrent.CopyOnWriteArrayList<>();
        java.util.logging.Logger log = java.util.logging.Logger.getLogger(
                AzureKeyVaultSecretProvider.class.getName());
        java.util.logging.Handler handler = new java.util.logging.Handler() {
            @Override
            public void publish(java.util.logging.LogRecord record) {
                said.add(record.getMessage());
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        log.addHandler(handler);
        try {
            Instant past = Instant.parse("2026-01-01T00:00:00Z");
            for (int login = 0; login < 100; login++) {
                assertNull(AzureKeyVaultSecretProvider.stillMeant(past, "orders-db-password"));
            }
            assertEquals(1, said.stream().filter(m -> m.contains("orders-db-password")).count(),
                    said.toString());
            AzureKeyVaultSecretProvider.stillMeant(past.plusSeconds(86_400), "orders-db-password");
            assertEquals(2, said.stream().filter(m -> m.contains("orders-db-password")).count(),
                    "a moved expiry, still past, is said again");
        } finally {
            log.removeHandler(handler);
        }
    }
}
