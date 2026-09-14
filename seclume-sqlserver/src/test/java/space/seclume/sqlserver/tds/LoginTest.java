package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretProvider;

/**
 * The complete login to a <b>real</b> SQL Server: PRELOGIN, the TLS handshake
 * inside TDS, LOGIN7, token stream.
 *
 * <p>This is the point where the password really goes over the wire - and the
 * only way to check that the obfuscation, the UTF-16 encoding and the field
 * table are right together. One wrong byte in that table and the server
 * answers "Login failed" without saying why.
 *
 * <p>The password comes from a file, so over the path the library offers.
 */
class LoginTest {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", "db.example.invalid");
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);
    private static final String USER = "sa";

    private static Path passwordFile;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(passwordFile != null, "no .local-mssql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
    }

    /** PRELOGIN, TLS, LOGIN7 - and the server lets us in. */
    @Test
    void logsInThroughTlsInsideTds() throws Exception {
        try (TdsChannel channel = TdsChannel.connect(HOST, PORT, 10_000)) {
            PreLogin preLogin = new PreLogin();
            preLogin.exchange(channel, Tds.ENCRYPT_ON);
            assertTrue(preLogin.supportsEncryption(), "the server refuses encryption");

            // Self-signed certificate in the test container - hence
            // explicitly without verification, and only here.
            TdsTls tls = TdsTls.create(channel.raw(), HOST, PORT, true);
            tls.handshake();
            channel.useTls(tls);
            assertTrue(channel.isEncrypted());
            System.out.println("TLS: " + tls.protocol() + " / " + tls.cipherSuite());

            Login7.send(channel, new Login7.Settings(HOST, "master", USER,
                    new FileSecretProvider(passwordFile, 256)));

            LoginResponse response = new LoginResponse();
            response.read(channel);
            assertNull(response.failure(),
                    () -> "login failed: " + response.failure().getMessage());
            assertTrue(response.isLoggedIn(), "no LOGINACK arrived");
            System.out.println("LOGINACK: server=" + response.serverName()
                    + ", database=" + response.database()
                    + ", packetSize=" + response.packetSize());
        }
    }

    /** A wrong password has to be rejected cleanly, not hang. */
    @Test
    void aWrongPasswordIsRejectedWithAnError() throws Exception {
        byte[] wrong = "definitiv-falsch-9#".getBytes(StandardCharsets.UTF_8);
        SecretProvider provider = new CallbackSecretProvider(256, target -> {
            for (int i = 0; i < wrong.length; i++) {
                target.set(ValueLayout.JAVA_BYTE, i, wrong[i]);
            }
            return wrong.length;
        });

        try (TdsChannel channel = TdsChannel.connect(HOST, PORT, 10_000)) {
            new PreLogin().exchange(channel, Tds.ENCRYPT_ON);
            TdsTls tls = TdsTls.create(channel.raw(), HOST, PORT, true);
            tls.handshake();
            channel.useTls(tls);

            Login7.send(channel, new Login7.Settings(HOST, "master", USER, provider));
            LoginResponse response = new LoginResponse();
            response.read(channel);

            assertNotNull(response.failure(), "the server accepted a wrong password");
            assertEquals("28000", response.failure().getSQLState());
            assertEquals(18456, response.failure().getErrorCode(),
                    "expected 'Login failed for user', got: " + response.failure().getMessage());
        }
    }
}
