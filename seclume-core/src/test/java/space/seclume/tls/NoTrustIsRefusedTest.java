package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * Encryption without authentication is asked for by name -
 * {@code connectWithoutAuthenticating} - so that it is visible where it is
 * done. {@code connect} with a null trust is a mistake, refused before a
 * byte is sent: the two overloads with ALPN and with the versions to offer
 * took it as "do not check the server" without a word.
 */
class NoTrustIsRefusedTest {

    @Test
    void everyConnectRefusesANullTrust() {
        List<Executable> calls = List.of(
                () -> ClientHandshake.connect(null, "db.example.com", null),
                () -> ClientHandshake.connect(null, "db.example.com", null, null),
                () -> ClientHandshake.connect(null, "db.example.com", null, null, "tds/8.0"),
                () -> ClientHandshake.connect(null, "db.example.com", null, null, null,
                        ClientHello.Offer.TLS12));
        for (Executable call : calls) {
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class, call);
            assertTrue(refused.getMessage().contains("connectWithoutAuthenticating"),
                    refused.getMessage());
        }
    }
}
