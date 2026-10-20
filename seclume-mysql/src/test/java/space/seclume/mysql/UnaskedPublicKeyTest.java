package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.sql.SQLException;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;

/**
 * A public key the driver did not ask for is not used.
 *
 * <p>On an unencrypted connection the password goes out RSA-encrypted under
 * the key the server sends - which is why fetching that key is off unless
 * {@code allowPublicKeyRetrieval} says otherwise: on the way there, anybody
 * can answer. Until 20.10.2026 that switch guarded only the request. A key
 * that simply arrived, as {@code AuthMoreData}, at any point of the login and
 * whatever the plugin, was taken and the password encrypted under it - so a
 * man in the middle had only to send his own key, and the setting meant to
 * stop him did not come into it. Default TLS is {@code prefer}, which the same
 * man in the middle can turn into no TLS.
 */
class UnaskedPublicKeyTest {

    private static final String USER = "seclume_test";
    private static final String PASSWORD = "ein Testpasswort";

    @Test
    void aKeyNobodyAskedForIsRefusedAndNothingIsEncryptedUnderIt() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            server.offerPublicKeyUnasked(pem()).start();
            SQLException refused = assertThrows(SQLException.class,
                    () -> MySession.open(new MySession.Settings("127.0.0.1", server.port(),
                            "testdb", USER, secret())).close());
            assertEquals("28000", refused.getSQLState(), refused.getMessage());
            assertTrue(refused.getMessage().contains("did not ask"), refused.getMessage());
            server.awaitDone();
            server.rethrowFailure();
            assertNull(server.answerToUnaskedKey(),
                    "the driver answered the unasked key - with the password under it");
        }
    }

    private static byte[] pem() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(generator.generateKeyPair().getPublic().getEncoded());
        return ("-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

    private static SecretProvider secret() {
        byte[] bytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        return new CallbackSecretProvider(256, target -> {
            for (int i = 0; i < bytes.length; i++) {
                target.set(ValueLayout.JAVA_BYTE, i, bytes[i]);
            }
            return bytes.length;
        });
    }
}
