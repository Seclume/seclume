package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.mysql.MySession;
import space.seclume.secret.SecretProviders;
import space.seclume.tck.NoSecretInHeap;

/**
 * A MySQL server held to TLS 1.2 ({@code --tls-version=TLSv1.2}) - what MySQL
 * 5.7 and many managed instances still are - reached on seclume's own stack,
 * with the password nowhere on the heap.
 *
 * <p>MySQL is the server to prove this against: inside TLS its
 * {@code caching_sha2_password} full authentication sends the password itself,
 * so every byte of it passes through the TLS record layer. With the JDK's TLS
 * that layer copies it through short-lived heap arrays; here it does not.
 *
 * <p>Needs {@code seclume.mytls12.host} and {@code .port} and a
 * {@code .local-mytls12-password}; skipped otherwise.
 */
@Timeout(120)
class LocalMyTls12Test {

    private static final String HOST = System.getProperty("seclume.mytls12.host", "127.0.0.1");
    private static final int PORT = Integer.getInteger("seclume.mytls12.port", 3310);
    private static Path password;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(".local-mytls12-password"),
                Path.of("..", ".local-mytls12-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mytls12-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no TLS 1.2 MySQL on " + HOST + ":" + PORT);
        }
    }

    private static MySession.Settings settings(TlsStack stack) throws SQLException {
        return new MySession.Settings(HOST, PORT, "seclume_test", "seclume_test",
                SecretProviders.of(Map.of("provider", "file", "path", password.toString())),
                "seclume", 5_000, false, HostList.of(HOST, PORT), ResultLimit.NONE,
                TlsMode.REQUIRE, stack);
    }

    @Test
    void theDefaultStackSpeaksTls12AndKeepsThePasswordOffTheHeap() throws Exception {
        try (MySession session = MySession.open(settings(TlsStack.AUTO))) {
            String tls = session.tlsDescription();
            assertTrue(tls.startsWith("TLSv1.2 / TLS_ECDHE_") && tls.endsWith(" (seclume)"), tls);
            assertEquals("TLSv1.2", session.askOneValue(
                    "select variable_value from performance_schema.session_status "
                            + "where variable_name = 'Ssl_version'"));
            NoSecretInHeap.assertAbsent(password);
        }
    }
}
