package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;

import org.junit.jupiter.api.Test;

import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * MariaDB's {@code client_ed25519} and {@code parsec} against the fake
 * server, which checks the signatures with the JDK: the switch, parsec's
 * request for the ext-salt, the answer's layout and sequence numbers - and a
 * wrong password refused, with nothing left open. The real server is in
 * {@code LocalMariaDbEd25519Test}.
 */
class Ed25519LoginTest {

    private static final String USER = "ed_user";

    private static SecretProvider secret(String password) {
        byte[] bytes = password.getBytes(StandardCharsets.UTF_8);
        return new CallbackSecretProvider(256, target -> {
            for (int i = 0; i < bytes.length; i++) {
                target.set(ValueLayout.JAVA_BYTE, i, bytes[i]);
            }
            return bytes.length;
        });
    }

    private static MySession.Settings settings(FakeMySqlServer server, String password) {
        return new MySession.Settings("127.0.0.1", server.port(), "testdb", USER,
                secret(password));
    }

    @Test
    void clientEd25519() throws Exception {
        loginSucceeds("client_ed25519");
    }

    @Test
    void parsec() throws Exception {
        loginSucceeds("parsec");
    }

    @Test
    void aWrongPasswordIsRefused() throws Exception {
        for (String plugin : new String[] {"client_ed25519", "parsec"}) {
            long open = SecretScope.open();
            try (FakeMySqlServer server = new FakeMySqlServer(USER, "secret")) {
                server.switchToSignature(plugin).start();
                SQLException refused = assertThrows(SQLException.class, () -> MySession.open(
                        settings(server, "not the secret")).close(), plugin);
                assertTrue(refused.getMessage().contains("Access denied"), refused.getMessage());
                server.awaitDone();
                server.rethrowFailure();
            }
            assertEquals(open, SecretScope.open());
        }
    }

    private static void loginSucceeds(String plugin) throws Exception {
        long open = SecretScope.open();
        try (FakeMySqlServer server = new FakeMySqlServer(USER, "secret")) {
            server.switchToSignature(plugin).start();
            try (MySession session = MySession.open(settings(server, "secret"))) {
                assertEquals(plugin, session.authenticationMethod());
            }
            server.rethrowFailure();
        }
        assertEquals(open, SecretScope.open());
    }
}
