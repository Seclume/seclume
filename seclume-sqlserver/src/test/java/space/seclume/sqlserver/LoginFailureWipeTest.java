package space.seclume.sqlserver;

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

import space.seclume.internal.jdbc.HostList;
import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.sqlserver.tds.TdsSession;
import space.seclume.tck.BreakableRelay;
import space.seclume.tck.TestHosts;

/**
 * A SQL Server login that goes wrong leaves no password behind.
 *
 * <p>The same question the PostgreSQL and MySQL modules already ask, asked of
 * the third handshake - and it is the one that deserves it most. <b>LOGIN7
 * obfuscates the password with a XOR that needs no key</b>, so the driver does
 * not merely hold the secret, it writes a transformation of it into a packet
 * buffer. That transformation is worth exactly as much to an attacker as the
 * password, and it is a second place a wipe can be forgotten. The three logins
 * share nothing but {@link SecretScope}: a wipe that holds in one says nothing
 * about the others.
 *
 * <p><b>Measured, not asserted.</b> {@link SecretScope#open()} has to be back
 * where it started, and {@link SecretScope#allocations()} has to have moved -
 * without the second check a test would pass whenever an early error skipped
 * the login altogether, which is the failure mode that makes this kind of test
 * worthless.
 *
 * <p><b>Why a real server.</b> SQL Server refuses to log in without TLS - this
 * driver's own rule, because that XOR travels in the clear otherwise - so a
 * fake would have to carry a complete TLS handshake before it reached anything
 * interesting, and a half-built handshake is a test that passes for the wrong
 * reason. The login here is real all the way; what is arranged is only when it
 * stops, through {@link BreakableRelay}.
 */
@Timeout(120)
class LoginFailureWipeTest {

    private String host;
    private int port;
    private Path password;

    @BeforeEach
    void findTheServer() {
        host = System.getProperty("seclume.mssql.host", TestHosts.database());
        Assumptions.assumeTrue(host != null, "no SQL Server host configured");
        port = Integer.getInteger("seclume.mssql.port", 1433);
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mssql-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no SQL Server on " + host + ":" + port);
        }
    }

    private TdsSession.Settings settings(String at, int atPort,
                                         space.seclume.secret.SecretProvider secret) {
        return new TdsSession.Settings(at, atPort, "master", "sa", secret,
                "wipe-test", 10_000, true, HostList.of(at, atPort));
    }

    /**
     * The commonest failure there is: the password is wrong.
     *
     * <p>By then the secret has been read, obfuscated, written into a LOGIN7
     * packet and sent. The error arrives with the scope still open and unwinds
     * through it.
     */
    @Test
    void aRejectedPasswordWipesIt() throws Exception {
        long open = SecretScope.open();
        long read = SecretScope.allocations();

        SQLException refused = assertThrows(SQLException.class,
                () -> TdsSession.open(settings(host, port, wrongPassword())));
        assertTrue(String.valueOf(refused.getMessage()).toLowerCase(java.util.Locale.ROOT)
                        .contains("login"),
                "the server should have refused the login: " + refused.getMessage());

        assertTrue(SecretScope.allocations() > read,
                "the login never got as far as reading the secret - then this proves nothing");
        assertEquals(open, SecretScope.open(), "a secret was left open after a refused login");
    }

    /**
     * The connection dies at the worst possible moment: while the password is
     * in memory.
     *
     * <p>Arranged exactly rather than approximately. The relay is cut from
     * inside the secret callback - so the driver holds a live secret, in a
     * scope it has just opened, and the very next thing it does is write into
     * a socket that is already gone. No orderly protocol error, no server to
     * be polite with, just an {@code IOException} out of the middle of the
     * handshake. That is where a wipe gets skipped.
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
                    () -> TdsSession.open(settings("127.0.0.1", relay.port(), secret)));
            assertTrue(relay.connections() > 0, "the driver should have gone through the relay");
        }

        assertTrue(SecretScope.allocations() > read,
                "the secret was never read - then this proves nothing");
        assertEquals(open, SecretScope.open(),
                "a secret was left open when the connection died mid-login");
    }

    /**
     * A server that is not there is never asked for a secret.
     *
     * <p>The opposite assertion from the two above, and it is the one that
     * keeps them honest: a driver that read the credential before it had
     * anywhere to send it would pass those two and still be wrong, because a
     * connection that never happened has no business touching a password.
     */
    @Test
    void anUnreachableServerNeverAsksForTheSecret() throws Exception {
        long open = SecretScope.open();
        long read = SecretScope.allocations();

        int gone = aPortNobodyAnswers();

        assertThrows(SQLException.class,
                () -> TdsSession.open(settings("127.0.0.1", gone,
                        new FileSecretProvider(password, 256))));

        assertEquals(read, SecretScope.allocations(),
                "the secret was read although there was nothing to log in to");
        assertEquals(open, SecretScope.open());
    }

    /**
     * A loopback port that really is dead, proven by trying it.
     *
     * <p>Binding an ephemeral port and closing it again is the obvious way to
     * get one, and it is wrong on a busy machine. Java opens a
     * {@code ServerSocket} with {@code SO_REUSEADDR}, so binding
     * {@code 127.0.0.1:P} succeeds even while something else holds
     * {@code 0.0.0.0:P} - and when that something is docker's proxy for a
     * service container, closing our listener leaves the port answering, on
     * behalf of a real database. The connection then logs in, nothing is
     * thrown, and the test fails claiming the driver read a secret it never
     * read.
     *
     * <p>That is exactly what happened in CI and not once locally, because
     * the collision needs the runner's random service port to land on the
     * ephemeral one we drew. So the port is <b>probed</b> rather than assumed:
     * a connect that is refused is the only evidence that nobody is there.
     */
    private static int aPortNobodyAnswers() throws IOException {
        for (int attempt = 0; attempt < 20; attempt++) {
            int candidate;
            try (java.net.ServerSocket probe = new java.net.ServerSocket()) {
                probe.bind(new java.net.InetSocketAddress(
                        java.net.InetAddress.getLoopbackAddress(), 0));
                candidate = probe.getLocalPort();
            }
            try (java.net.Socket knock = new java.net.Socket()) {
                knock.connect(new java.net.InetSocketAddress(
                        java.net.InetAddress.getLoopbackAddress(), candidate), 500);
            } catch (IOException refused) {
                return candidate;
            }
            // Somebody answered on a port we had just given up, so it was
            // never ours alone. Draw another one.
        }
        throw new IOException("twenty ephemeral ports in a row were still answering "
                + "after being closed - this machine has something bound to 0.0.0.0 "
                + "across the ephemeral range");
    }

    private space.seclume.secret.SecretProvider wrongPassword() {
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
