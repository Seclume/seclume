package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.Transport;

/**
 * Server certificates with the keys a client has to name a signature scheme
 * for: Ed25519 ({@code ed25519}) and an RSA key restricted to PSS
 * ({@code rsa_pss_pss_sha256}). A JSSE server holding one can only sign with
 * that scheme; a client that does not offer it gets a handshake_failure -
 * which is what seclume did before. Over TLS 1.3 and the TLS 1.2 profile,
 * where the Ed25519 certificate rides on an ECDHE_ECDSA suite (RFC 8422).
 */
@Timeout(120)
class CertificateKeyKindsTest {

    private static final String HOSTNAME = "db.example.com";

    private static TestCertificates certificates;
    private static KeyStore trustStore;
    private static SSLContext ed25519;
    private static SSLContext rsaPss;

    @BeforeAll
    static void startAnAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        trustStore = certificates.trustStore();
        ed25519 = contextFor(certificates.issueWith("ed25519-server",
                List.of("-keyalg", "Ed25519"),
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth").keystore());
        rsaPss = contextFor(certificates.issueWith("pss-server",
                List.of("-keyalg", "RSASSA-PSS", "-keysize", "2048"),
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth").keystore());
    }

    @AfterAll
    static void removeTheAuthority() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    @ParameterizedTest(name = "{0} over {1}")
    @CsvSource({"ed25519, TLSv1.3", "ed25519, TLSv1.2", "rsa-pss, TLSv1.3", "rsa-pss, TLSv1.2"})
    void aServerWithThisKeyIsReached(String kind, String protocol) throws Exception {
        SSLContext context = kind.equals("ed25519") ? ed25519 : rsaPss;
        try (EchoServer server = EchoServer.start(context,
                socket -> socket.setEnabledProtocols(new String[] {protocol}));
                Transport socket = SocketTransport.wrap(java.nio.channels.SocketChannel.open(
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), server.port())));
                TlsConnection tls = ClientHandshake.connect(socket, HOSTNAME,
                        CertificateTrust.of(trustStore))) {
            assertTrue(tls.description().startsWith(protocol), tls.description());
            byte[] sent = ("over " + kind).getBytes(StandardCharsets.US_ASCII);
            tls.write(ByteBuffer.wrap(sent));
            ByteBuffer back = ByteBuffer.allocate(sent.length);
            while (back.hasRemaining()) {
                assertTrue(tls.read(back) >= 0, "the echo ended early");
            }
            assertArrayEquals(sent, back.array());
        }
    }

    private static SSLContext contextFor(Path keystore) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        TrustManagerFactory trusts =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trusts.init(trustStore);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), trusts.getTrustManagers(), null);
        return context;
    }
}
