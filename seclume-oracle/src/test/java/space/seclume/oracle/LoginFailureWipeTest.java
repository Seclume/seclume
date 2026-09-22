package space.seclume.oracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.tck.BreakableRelay;
import space.seclume.tck.TestHosts;

/**
 * An Oracle login that goes wrong leaves no password behind.
 *
 * <p>The fourth handshake, and the longest. PostgreSQL reads the password and
 * may use it over several SASL rounds; MySQL hashes it into the first packet
 * it sends; SQL Server obfuscates it with a keyless XOR. <b>Oracle does more
 * than any of them:</b> the password goes into a key derivation, the derived
 * key decrypts a challenge from the server, and the answer goes back
 * encrypted. Every one of those steps is a place where material derived from
 * the password exists, and every early exit between them is a place where a
 * wipe can be skipped - which is exactly what this asks about.
 *
 * <p><b>Measured, not asserted.</b> {@link SecretScope#open()} has to be back
 * where it started, and {@link SecretScope#allocations()} has to have moved.
 * Without the second check the test would pass whenever an early error skipped
 * the login altogether - the failure mode that makes this kind of test
 * worthless.
 */
@Timeout(120)
class LoginFailureWipeTest {

    private String host;
    private int port;
    private String service;
    private String user;
    private Path password;

    @BeforeEach
    void findTheServer() {
        host = System.getProperty("seclume.oracle.host", TestHosts.database());
        Assumptions.assumeTrue(host != null, "no Oracle host configured");
        port = Integer.getInteger("seclume.oracle.port", 1521);
        service = System.getProperty("seclume.oracle.service", "FREEPDB1");
        user = System.getProperty("seclume.oracle.user", "seclume_test");
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no Oracle on " + host + ":" + port);
        }
    }

    private OracleSession.Settings settings(String at, int atPort, SecretProvider secret) {
        return new OracleSession.Settings(at, atPort, service, user, secret, 10_000);
    }

    /**
     * The commonest failure there is: the password is wrong.
     *
     * <p>By this point the secret has been read and run through the key
     * derivation, and the refusal arrives with the scope still open.
     *
     * <p><b>This test found a bug rather than confirming a wipe.</b> Oracle
     * answers a refused login the way it answers every other failure - a break
     * marker and a reset marker first, the error only after the client has
     * answered them - and the login path did not answer them. The driver saw a
     * MARKER where it expected data and reported "the login failed" with
     * SQLState 08001. That is not merely a poor message: 08 means the
     * connection, and a host list takes a connection failure to the next
     * server, so one wrong password would be offered to every node in turn.
     * See {@code NsChannel.answerMarkers}, which now has the handshake once
     * instead of in one caller out of two.
     */
    @Test
    void aRejectedPasswordWipesIt() throws Exception {
        long open = SecretScope.open();
        long read = SecretScope.allocations();

        SQLException refused = assertThrows(SQLException.class,
                () -> OracleSession.open(settings(host, port, wrongPassword())));
        assertTrue(String.valueOf(refused.getMessage()).contains("refused the login"),
                "the server should have refused the login: " + refused.getMessage());
        // The server's own sentence, not only ours: ORA-01017 is a wrong
        // password, ORA-28000 a locked account, ORA-28001 an expired one, and
        // the right thing to do differs for each.
        assertTrue(String.valueOf(refused.getMessage()).contains("ORA-01017"),
                "the refusal should carry the server's reason: " + refused.getMessage());
        // 28000 and not 08001, which is what this test found: a refused
        // password used to arrive as a connection failure, and a host list
        // takes a connection failure to the next server - where the same
        // password is refused again, on every node in turn.
        assertEquals("28000", refused.getSQLState(),
                "a refused password is an authentication failure, not a connection one");

        assertTrue(SecretScope.allocations() > read,
                "the login never got as far as reading the secret - then this proves nothing");
        assertEquals(open, SecretScope.open(), "a secret was left open after a refused login");
    }

    /**
     * The connection dies while the password is in memory.
     *
     * <p>Arranged exactly rather than approximately: the relay is cut from
     * inside the secret callback, so the driver holds a live secret in a scope
     * it has just opened, and the next thing it does is write into a socket
     * that is already gone. No orderly server error to unwind through, just an
     * {@code IOException} out of the middle of the key exchange.
     */
    @Test
    void aConnectionThatDiesWhileTheSecretIsHeldStillWipesIt() throws Exception {
        long open = SecretScope.open();
        long read = SecretScope.allocations();

        try (BreakableRelay relay = BreakableRelay.to(host, port)) {
            CallbackSecretProvider secret = new CallbackSecretProvider(256, target -> {
                try {
                    relay.cut();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
                return writeInto(target, readPassword());
            });

            assertThrows(SQLException.class,
                    () -> OracleSession.open(settings("127.0.0.1", relay.port(), secret)));
            assertTrue(relay.connections() > 0, "the driver should have gone through the relay");
        }

        assertTrue(SecretScope.allocations() > read,
                "the secret was never read - then this proves nothing");
        assertEquals(open, SecretScope.open(),
                "a secret was left open when the connection died mid-login");
    }

    /**
     * A listener that is not there is never asked for a secret.
     *
     * <p>The assertion that keeps the other two honest: a driver that read the
     * credential before it had anywhere to send it would pass both of them and
     * still be wrong.
     */
    @Test
    void anUnreachableListenerNeverAsksForTheSecret() throws Exception {
        long open = SecretScope.open();
        long read = SecretScope.allocations();

        BreakableRelay relay = BreakableRelay.to(host, port);
        int gone = relay.port();
        relay.close();

        assertThrows(SQLException.class,
                () -> OracleSession.open(settings("127.0.0.1", gone,
                        new FileSecretProvider(password, 256))));

        assertEquals(read, SecretScope.allocations(),
                "the secret was read although there was nothing to log in to");
        assertEquals(open, SecretScope.open());
    }

    private SecretProvider wrongPassword() {
        return new CallbackSecretProvider(256,
                target -> writeInto(target, "not-the-password-Aa1!".getBytes(
                        StandardCharsets.UTF_8)));
    }

    private byte[] readPassword() {
        try {
            return Files.readAllBytes(password);
        } catch (IOException e) {
            throw new IllegalStateException("the password file moved", e);
        }
    }

    private static int writeInto(MemorySegment target, byte[] bytes) {
        int length = trimmed(bytes);
        MemorySegment.copy(MemorySegment.ofArray(bytes), ValueLayout.JAVA_BYTE, 0,
                target, ValueLayout.JAVA_BYTE, 0, length);
        return length;
    }

    /** The file ends with a newline more often than not. */
    private static int trimmed(byte[] bytes) {
        int length = bytes.length;
        while (length > 0 && (bytes[length - 1] == '\n' || bytes[length - 1] == '\r')) {
            length--;
        }
        return length;
    }
}
