package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Collections;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.Transport;
import space.seclume.internal.Transports;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;

/**
 * A certificate from a CA the JVM does not know: refused as before, accepted
 * with {@code tlsRootCert} naming that CA, accepted with {@code tlsPin}
 * naming the server's key - and a wrong pin refused. On both TLS stacks.
 */
@Timeout(120)
class TrustChoiceTest {

    private static final String HOSTNAME = "db.example.com";
    private static TestCertificates certificates;
    private static SSLContext serverContext;
    private static String serverPin;

    @TempDir
    static Path dir;
    private static Path caFile;

    @BeforeAll
    static void anAuthorityTheJvmDoesNotKnow() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issue("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        serverContext = contextPresenting(server.keystore());
        serverPin = TrustChoice.pinOf(server.certificate());
        KeyStore anchors = certificates.trustStore();
        StringBuilder pem = new StringBuilder();
        for (String alias : Collections.list(anchors.aliases())) {
            Certificate ca = anchors.getCertificate(alias);
            pem.append("-----BEGIN CERTIFICATE-----\n")
                    .append(Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                            .encodeToString(ca.getEncoded()))
                    .append("\n-----END CERTIFICATE-----\n");
        }
        caFile = Files.writeString(dir.resolve("ca.pem"), pem);
    }

    @AfterAll
    static void removeTheAuthority() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    @ParameterizedTest
    @EnumSource(TlsStack.class)
    void anUnknownCaIsRefusedAsBefore(TlsStack stack) {
        assertThrows(IOException.class, () -> handshake(stack, null));
    }

    @ParameterizedTest
    @EnumSource(TlsStack.class)
    void theCaFileOfThisConnectionIsTrusted(TlsStack stack) throws Exception {
        handshake(stack, "tlsRootCert=" + caFile.toString().replace('\\', '/'));
    }

    @ParameterizedTest
    @EnumSource(TlsStack.class)
    void thePinnedKeyIsTrusted(TlsStack stack) throws Exception {
        handshake(stack, "tlsPin=" + serverPin);
    }

    @ParameterizedTest
    @EnumSource(TlsStack.class)
    void aWrongPinIsRefusedAndSaysWhatItGot(TlsStack stack) {
        String wrong = "sha256/" + Base64.getEncoder().encodeToString(new byte[32]);
        IOException refused = assertThrows(IOException.class,
                () -> handshake(stack, "tlsPin=" + wrong));
        assertTrue(refused.getMessage().contains("not the pinned one"), refused.getMessage());
        assertTrue(refused.getMessage().contains(serverPin), refused.getMessage());
    }

    @org.junit.jupiter.api.Test
    void aPinThatIsNotASha256IsRefusedAtOnce() {
        assertThrows(SQLException.class,
                () -> TrustChoice.of("jdbc:x://h/db?tlsPin=md5/abc", null));
        assertThrows(SQLException.class,
                () -> TrustChoice.of("jdbc:x://h/db?tlsPin=sha256/AAAA", null));
    }

    /** A verifying handshake to the echo server, with the trust the options name. */
    private static void handshake(TlsStack stack, String options) throws Exception {
        try (EchoServer server = EchoServer.start(serverContext);
             Transport socket = SocketTransport.connect(
                     InetAddress.getLoopbackAddress().getHostAddress(), server.port(), 10_000)) {
            TrustChoice.Choice choice = options == null ? null
                    : TrustChoice.of("jdbc:x://h/db?" + options, null);
            Transports.Opening<TlsLayer> open = () -> {
                try {
                    return TlsLayers.start(stack, socket, HOSTNAME, server.port(), true);
                } catch (IOException e) {
                    throw new SQLException(e.getMessage(), e);
                }
            };
            TlsLayer layer;
            try {
                layer = TrustChoice.using(choice, open);
            } catch (SQLException e) {
                throw e.getCause() instanceof IOException io ? io : new IOException(e);
            }
            try {
                byte[] hello = "hello".getBytes(StandardCharsets.US_ASCII);
                layer.write(ByteBuffer.wrap(hello));
                ByteBuffer back = ByteBuffer.allocate(hello.length);
                while (back.hasRemaining()) {
                    if (layer.read(back) < 0) {
                        throw new IOException("closed");
                    }
                }
                assertArrayEquals(hello, back.array());
            } finally {
                layer.close();
            }
        }
    }

    private static SSLContext contextPresenting(Path keystore) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keys.getKeyManagers(), null, null);
        return context;
    }
}
