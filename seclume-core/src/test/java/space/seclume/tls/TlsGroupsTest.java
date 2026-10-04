package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.Transport;
import space.seclume.internal.jdbc.TlsStack;

/**
 * The key exchange groups against servers that allow exactly one of them -
 * the hardened configurations that would otherwise shut this client out.
 *
 * <p>A TLS 1.3 server limited to P-384 has no share for it in the first
 * ClientHello and has to ask with a HelloRetryRequest; one limited to X25519
 * finds its share at once. On TLS 1.2 the server names its curve in the
 * ServerKeyExchange. Each case sends data both ways afterwards, so a key
 * derived wrongly on either side shows up as a record that does not open.
 */
@Timeout(120)
class TlsGroupsTest {

    private static final String HOSTNAME = "db.example.com";
    private static TestCertificates certificates;
    private static SSLContext serverContext;

    @BeforeAll
    static void startAnAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issue("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        KeyManagerFactory keys = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (java.io.InputStream in = java.nio.file.Files.newInputStream(server.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        serverContext = SSLContext.getInstance("TLS");
        serverContext.init(keys.getKeyManagers(), null, null);
    }

    @AfterAll
    static void removeTheAuthority() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    @ParameterizedTest(name = "{0} with {1}")
    @CsvSource({"TLSv1.3, secp384r1, TLSv1.3, P-384",
            "TLSv1.3, x25519, TLSv1.3, X25519",
            "TLSv1.3, secp256r1, TLSv1.3, P-256",
            "TLSv1.2, secp384r1, TLSv1.2, ECDHE",
            "TLSv1.2, x25519, TLSv1.2, ECDHE"})
    void aServerWithOneGroupIsReached(String protocol, String group, String expectedVersion,
            String expectedGroup) throws Exception {
        try (EchoServer server = EchoServer.start(serverContext, socket -> {
            socket.setEnabledProtocols(new String[] {protocol});
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setNamedGroups(new String[] {group});
            socket.setSSLParameters(parameters);
        });
                Transport socket = SocketTransport.wrap(java.nio.channels.SocketChannel.open(
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), server.port())));
                TlsLayer tls = TlsLayers.start(TlsStack.SECLUME, socket, HOSTNAME, server.port(),
                        false)) {
            String description = tls.description();
            assertTrue(description.startsWith(expectedVersion) && description.contains(expectedGroup)
                    && description.endsWith(" (seclume)"), description);
            byte[] sent = ("over " + group).getBytes(StandardCharsets.US_ASCII);
            tls.write(ByteBuffer.wrap(sent));
            ByteBuffer back = ByteBuffer.allocate(sent.length);
            while (back.hasRemaining()) {
                assertTrue(tls.read(back) >= 0, "the echo ended early");
            }
            assertArrayEquals(sent, back.array());
        }
    }
}
