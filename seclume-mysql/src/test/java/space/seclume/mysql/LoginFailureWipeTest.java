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
 * A refused MySQL login leaves no password behind either.
 *
 * <p>The same question as {@code ConnectFailureWipeTest} in the PostgreSQL
 * module, asked of the second handshake. It is worth asking twice: the two
 * logins share nothing but {@link SecretScope}. PostgreSQL reads the password
 * once and may use it in several rounds of SASL; MySQL hashes it into the very
 * first packet it sends and finds out afterwards whether the server agreed. A
 * missing wipe in one says nothing about the other.
 *
 * <p>The fake server checks the hash before it refuses, so a driver that sent
 * nonsense could not pass this by being told "access denied" for the wrong
 * reason.
 */
class LoginFailureWipeTest {

    private static final String USER = "seclume_test";
    private static final String PASSWORD = "ein Testpasswort";

    private static SecretProvider secret() {
        byte[] bytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        return new CallbackSecretProvider(256, target -> {
            for (int i = 0; i < bytes.length; i++) {
                target.set(ValueLayout.JAVA_BYTE, i, bytes[i]);
            }
            return bytes.length;
        });
    }

    private static MySession.Settings settings(FakeMySqlServer server) {
        return new MySession.Settings("127.0.0.1", server.port(), "testdb", USER, secret());
    }

    @Test
    void aRefusedLoginWipesThePassword() throws Exception {
        long open = SecretScope.open();
        long read = SecretScope.allocations();

        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            server.rejectLogin().start();

            SQLException refused = assertThrows(SQLException.class,
                    () -> MySession.open(settings(server)).close());
            assertTrue(refused.getMessage().contains("Access denied"), refused.getMessage());
            server.awaitDone();
            server.rethrowFailure();
        }

        assertTrue(SecretScope.allocations() > read,
                "the login never read the secret - then this test proves nothing");
        assertEquals(open, SecretScope.open());
    }

    /**
     * A server that cannot be reached is never worth a secret.
     *
     * <p>The stronger statement of the two, and the cheaper one: the login
     * failed before there was anyone to log in to, so the secret source must
     * not have been touched at all. It matters beyond tidiness because of
     * failover - a host list of four dead servers must not mean four reads
     * from a Vault, four smartcard prompts or four audit entries.
     */
    @Test
    void anUnreachableServerNeverAsksForTheSecret() throws Exception {
        int port;
        try (java.net.ServerSocket probe = new java.net.ServerSocket(
                0, 1, java.net.InetAddress.getLoopbackAddress())) {
            port = probe.getLocalPort();
        }
        // The socket is closed again, so nothing is listening on that port.

        long open = SecretScope.open();
        long read = SecretScope.allocations();

        assertThrows(SQLException.class, () -> MySession.open(
                new MySession.Settings("127.0.0.1", port, "testdb", USER, secret())).close());

        assertEquals(read, SecretScope.allocations(),
                "the secret was read although no connection was ever made");
        assertEquals(open, SecretScope.open());
    }
}
