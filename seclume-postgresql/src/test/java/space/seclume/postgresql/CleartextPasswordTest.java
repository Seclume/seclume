package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.sql.SQLInvalidAuthorizationSpecException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;

/**
 * PostgreSQL's {@code password} method - and {@code ldap}, {@code pam},
 * {@code radius}, which ask the same way - wants the password itself. It goes
 * only to a server whose certificate was checked: over TLS that checked
 * nothing, a server in the middle that terminated it asked and was answered.
 */
@Timeout(120)
class CleartextPasswordTest {

    private static final String PASSWORD = "hunter2-hunter2";

    @TempDir
    static Path directory;
    private static SSLContext serverContext;
    private static String serverPin;

    @BeforeAll
    static void aSelfMadeCertificate() throws Exception {
        Path store = directory.resolve("server.p12");
        Process keytool = new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "server", "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=fake-postgres", "-ext", "san=ip:127.0.0.1", "-validity", "2",
                "-storetype", "PKCS12", "-keystore", store.toString(),
                "-storepass", "fake-postgres", "-keypass", "fake-postgres")
                .redirectErrorStream(true).start();
        keytool.getInputStream().readAllBytes();
        assertTrue(keytool.waitFor(60, TimeUnit.SECONDS) && keytool.exitValue() == 0,
                "keytool failed");
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(store)) {
            keys.load(in, "fake-postgres".toCharArray());
        }
        serverPin = TrustChoice.pinOf((X509Certificate) keys.getCertificate("server"));
        KeyManagerFactory factory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keys, "fake-postgres".toCharArray());
        serverContext = SSLContext.getInstance("TLSv1.3");
        serverContext.init(factory.getKeyManagers(), null, null);
    }

    /**
     * A PostgreSQL that says yes to the SSLRequest with its own certificate,
     * reads the startup message inside TLS, asks for the password itself and
     * returns what comes back - the PasswordMessage's body, or null for nothing.
     */
    private static CompletableFuture<byte[]> serve(ServerSocket listener) {
        return CompletableFuture.supplyAsync(() -> {
            try (Socket plain = listener.accept()) {
                plain.setSoTimeout(30_000);
                InputStream request = plain.getInputStream();
                request.readNBytes(readInt(request) - 4);           // SSLRequest
                plain.getOutputStream().write('S');
                plain.getOutputStream().flush();
                SSLSocket tls = (SSLSocket) serverContext.getSocketFactory()
                        .createSocket(plain, "127.0.0.1", plain.getPort(), true);
                tls.setUseClientMode(false);
                tls.startHandshake();
                InputStream in = tls.getInputStream();
                OutputStream out = tls.getOutputStream();
                in.readNBytes(readInt(in) - 4);                      // startup message
                out.write('R');
                writeInt(out, 8);
                writeInt(out, 3);                                    // the password itself
                out.flush();
                int tag;
                try {
                    tag = in.read();
                } catch (IOException closed) {
                    return null;
                }
                if (tag != 'p') {
                    return null;
                }
                byte[] body = in.readNBytes(readInt(in) - 4);
                byte[] error = "SFATAL\0C28P01\0Mno\0\0".getBytes(StandardCharsets.US_ASCII);
                out.write('E');
                writeInt(out, 4 + error.length);
                out.write(error);
                out.flush();
                return body;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }

    private static int readInt(InputStream in) throws IOException {
        byte[] four = in.readNBytes(4);
        if (four.length < 4) {
            throw new IOException("the client hung up");
        }
        return (four[0] & 0xff) << 24 | (four[1] & 0xff) << 16 | (four[2] & 0xff) << 8
                | (four[3] & 0xff);
    }

    private static void writeInt(OutputStream out, int value) throws IOException {
        out.write(value >>> 24);
        out.write(value >>> 16);
        out.write(value >>> 8);
        out.write(value);
    }

    private static SecretProvider password() {
        return new CallbackSecretProvider(64, target -> {
            byte[] bytes = PASSWORD.getBytes(StandardCharsets.US_ASCII);
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
    }

    private static PgSession.Settings settings(int port, TlsMode tls) {
        return new PgSession.Settings("127.0.0.1", port, "app", "app", password(),
                "seclume-test", 10_000, HostList.of("127.0.0.1", port), ResultLimit.NONE, tls,
                TlsStack.SECLUME);
    }

    private static ServerSocket listener() throws IOException {
        return new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
    }

    @Test
    void notOverTlsThatCheckedNothing() throws Exception {
        for (TlsMode mode : new TlsMode[] {TlsMode.PREFER, TlsMode.REQUIRE}) {
            try (ServerSocket listener = listener()) {
                CompletableFuture<byte[]> received = serve(listener);
                SQLInvalidAuthorizationSpecException refused = assertThrows(
                        SQLInvalidAuthorizationSpecException.class,
                        () -> PgSession.open(settings(listener.getLocalPort(), mode)).close());
                assertEquals("28000", refused.getSQLState());
                assertTrue(refused.getMessage().contains("password authentication"),
                        refused.getMessage());
                assertTrue(refused.getMessage().contains("does not check it"),
                        refused.getMessage());
                assertNull(received.get(30, TimeUnit.SECONDS), "the password went out");
            }
        }
    }

    @Test
    void toThePinnedKey() throws Exception {
        try (ServerSocket listener = listener()) {
            CompletableFuture<byte[]> received = serve(listener);
            TrustChoice.Choice pin = TrustChoice.of("jdbc:x://h/db?tlsPin=" + serverPin, null);
            SQLException failed = assertThrows(SQLException.class, () -> TrustChoice.using(pin,
                    () -> PgSession.open(settings(listener.getLocalPort(), TlsMode.REQUIRE)))
                    .close());
            assertEquals("28P01", failed.getSQLState(), failed.getMessage());
            assertArrayEquals((PASSWORD + "\0").getBytes(StandardCharsets.US_ASCII),
                    received.get(30, TimeUnit.SECONDS));
        }
    }
}
