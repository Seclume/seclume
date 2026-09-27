package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.crypto.HybridMlKem;
import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;

/**
 * The post-quantum key exchange, end to end: the own stack against OpenSSL
 * 3.5's {@code s_server}, which knows X25519MLKEM768.
 *
 * <p>{@link ClientHelloGroupsTest} shows the hybrid is <i>offered</i>; this
 * shows it is <i>used</i> - a server that accepts nothing else completes the
 * handshake and serves a page, and says itself that it shared the hybrid. The
 * two controls make that worth something: the same server refuses the client
 * with the hybrid switched off, and a P-256-only server still gets a
 * connection.
 *
 * <p>Needs OpenSSL 3.5 or later, which most build machines do not have yet:
 * {@code SECLUME_OPENSSL35} names its {@code openssl} binary, and the JVM must
 * load the matching libcrypto ({@code LD_LIBRARY_PATH}). Without the variable
 * the test is skipped; with it, a libcrypto without ML-KEM is a failure, not a
 * skip - CI sets it so that this cannot quietly stop running.
 */
@Timeout(120)
class HybridHandshakeTest {

    private static final String OPENSSL = System.getenv("SECLUME_OPENSSL35");

    private static TestCertificates certificates;
    private static Path directory;
    private static Path certPem;
    private static Path keyPem;
    private static TrustChoice.Choice pin;

    @BeforeAll
    static void serverCertificate() throws Exception {
        Assumptions.assumeTrue(OPENSSL != null && !OPENSSL.isBlank(),
                "SECLUME_OPENSSL35 is not set - no OpenSSL 3.5 to test the hybrid against");
        assertTrue(HybridMlKem.available(), "SECLUME_OPENSSL35 is set, but the libcrypto this "
                + "JVM loads has no ML-KEM - LD_LIBRARY_PATH has to name OpenSSL 3.5's lib");
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");

        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issue("server",
                "san=dns:localhost", "ku:c=digitalSignature", "eku=serverAuth");
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(server.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        String alias = Collections.list(store.aliases()).stream()
                .filter(a -> isKey(store, a)).findFirst().orElseThrow();
        Key key = store.getKey(alias, TestCertificates.PASSWORD.toCharArray());

        directory = Files.createTempDirectory("seclume-pq");
        certPem = directory.resolve("cert.pem");
        keyPem = directory.resolve("key.pem");
        Files.writeString(certPem, pem("CERTIFICATE", server.certificate().getEncoded()));
        // A throwaway test key for the server process, never a client secret.
        Files.writeString(keyPem, pem("PRIVATE KEY", key.getEncoded()));
        pin = TrustChoice.of("x?tlsPin=" + TrustChoice.pinOf(server.certificate()),
                new Properties());
    }

    @AfterAll
    static void cleanUp() throws Exception {
        if (certificates != null) {
            certificates.close();
        }
        if (directory != null) {
            Files.deleteIfExists(certPem);
            Files.deleteIfExists(keyPem);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void aServerThatTakesOnlyTheHybridGetsIt() throws Exception {
        try (Server server = Server.start("X25519MLKEM768")) {
            Result result = fetch(server.port);
            assertTrue(result.description.contains("with X25519MLKEM768"), result.description);
            assertTrue(result.page.contains("Shared groups: X25519MLKEM768"), result.page);
        }
    }

    @Test
    void withoutTheHybridThatServerRefuses() throws Exception {
        try (Server server = Server.start("X25519MLKEM768")) {
            System.setProperty("seclume.tls.postQuantum", "false");
            try {
                Exception refused = assertThrows(Exception.class, () -> fetch(server.port));
                assertTrue(String.valueOf(refused.getMessage()).contains("handshake_failure"),
                        String.valueOf(refused.getMessage()));
            } finally {
                System.clearProperty("seclume.tls.postQuantum");
            }
        }
    }

    @Test
    void aServerWithoutTheHybridStillGetsP256() throws Exception {
        try (Server server = Server.start("P-256")) {
            Result result = fetch(server.port);
            assertFalse(result.description.contains("MLKEM"), result.description);
            assertTrue(result.page.contains("Shared groups: secp256r1"), result.page);
        }
    }

    private record Result(String description, String page) {
    }

    /** A handshake with the pinned certificate checked, then one request of s_server's -www page. */
    private static Result fetch(int port) throws Exception {
        TlsLayer tls = TrustChoice.using(pin, () -> {
            try {
                return TlsLayers.start(TlsStack.SECLUME,
                        SocketTransport.connect("localhost", port, 5000), "localhost", port, true);
            } catch (IOException e) {
                throw new SQLException(e.getMessage(), "08001", e);
            }
        });
        try (tls) {
            tls.write(ByteBuffer.wrap("GET / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.US_ASCII)));
            ByteBuffer in = ByteBuffer.allocate(1 << 16);
            while (in.hasRemaining() && tls.read(in) > 0) {
                // until the server closes
            }
            in.flip();
            return new Result(tls.description(), StandardCharsets.UTF_8.decode(in).toString());
        }
    }

    /** {@code openssl s_server} on an ephemeral port, TLS 1.3 and only the given groups. */
    private static final class Server implements AutoCloseable {

        final Process process;
        final int port;

        private Server(Process process, int port) {
            this.process = process;
            this.port = port;
        }

        static Server start(String groups) throws Exception {
            List<String> command = new ArrayList<>(List.of(OPENSSL, "s_server", "-accept", "0",
                    "-tls1_3", "-groups", groups, "-cert", certPem.toString(),
                    "-key", keyPem.toString(), "-www"));
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            BufferedReader out = new BufferedReader(new InputStreamReader(
                    process.getInputStream(), StandardCharsets.UTF_8));
            List<String> seen = new ArrayList<>();
            for (String line; (line = out.readLine()) != null; ) {
                seen.add(line);
                if (line.startsWith("ACCEPT ")) {
                    int port = Integer.parseInt(line.substring(line.lastIndexOf(':') + 1).trim());
                    Thread drain = new Thread(() -> {
                        try {
                            while (out.readLine() != null) {
                                // keep the pipe from filling
                            }
                        } catch (IOException ignored) {
                            // the server was stopped
                        }
                    }, "s_server-output");
                    drain.setDaemon(true);
                    drain.start();
                    return new Server(process, port);
                }
            }
            process.destroyForcibly();
            throw new IllegalStateException("s_server did not start: " + seen);
        }

        @Override
        public void close() {
            process.destroy();
            try {
                if (!process.waitFor(10, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
            } catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
            }
        }
    }

    private static boolean isKey(KeyStore store, String alias) {
        try {
            return store.isKeyEntry(alias);
        } catch (Exception e) {
            return false;
        }
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

}
