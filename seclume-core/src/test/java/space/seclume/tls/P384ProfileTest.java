package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.crypto.EcdsaSigner;
import space.seclume.internal.SocketTransport;
import space.seclume.internal.Transport;
import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;

/**
 * The P-384 profile FIPS and CNSA configurations ask for, against a JSSE
 * server held to it: a P-384 server certificate, the secp384r1 group and
 * nothing else, AES-256-GCM with SHA-384 only, and a client certificate
 * demanded - on P-384 as well, its key off the heap ({@link EcClientIdentity}).
 * The server verifies our CertificateVerify itself, so a wrong hash, a wrong
 * scheme or a DER a byte out ends as a refused handshake, not as a test
 * agreeing with itself.
 */
@Timeout(120)
@org.junit.jupiter.api.parallel.Isolated
class P384ProfileTest {

    private static final String HOSTNAME = "db.example.com";

    private static TestCertificates certificates;
    private static SSLContext serverContext;
    private static KeyStore trustStore;
    private static TestCertificates.Issued client;

    @BeforeAll
    static void startAnAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        Assumptions.assumeTrue(EcdsaSigner.available(),
                "off-heap ECDSA signing needs Windows or 64-bit Linux with libcrypto.so.3");
        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issueP384("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        client = certificates.issueP384("client", "ku:c=digitalSignature", "eku=clientAuth");
        trustStore = certificates.trustStore();
        serverContext = contextFor(server.keystore(), trustStore);
    }

    @AfterAll
    static void removeTheAuthority() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({"TLSv1.3, TLS_AES_256_GCM_SHA384",
            "TLSv1.2, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"})
    void theWholeProfileOnP384(String protocol, String suite, @TempDir Path dir)
            throws Exception {
        try (EcClientIdentity identity = identity(dir);
                EchoServer server = EchoServer.start(serverContext, socket -> {
                    socket.setNeedClientAuth(true);
                    socket.setEnabledProtocols(new String[] {protocol});
                    socket.setEnabledCipherSuites(new String[] {suite});
                    SSLParameters parameters = socket.getSSLParameters();
                    parameters.setNamedGroups(new String[] {"secp384r1"});
                    // P-384 for every handshake signature; the test CA itself signs
                    // with RSA, which the certificate chains need as well.
                    parameters.setSignatureSchemes(new String[] {"ecdsa_secp384r1_sha384",
                            "rsa_pkcs1_sha256"});
                    socket.setSSLParameters(parameters);
                });
                Transport socket = connectTo(server);
                TlsConnection tls = ClientHandshake.connect(socket, HOSTNAME,
                        CertificateTrust.of(trustStore), identity)) {
            assertEquals(EcdsaSigner.Curve.P384, identity.curve());
            assertEquals(HandshakeSignature.ECDSA_SECP384R1_SHA384, identity.signatureScheme());
            assertTrue(tls.description().startsWith(protocol + " / " + suite),
                    tls.description());
            byte[] sent = ("select 1 over " + protocol).getBytes(StandardCharsets.US_ASCII);
            tls.write(ByteBuffer.wrap(sent));
            assertArrayEquals(sent, readExactly(tls, sent.length),
                    "the server verified our P-384 certificate and the connection carries data");
        }
    }

    /** One key, several connections: loaded once, a fresh signature each time. */
    @Test
    void oneP384IdentitySignsForSeveralConnections(@TempDir Path dir) throws Exception {
        try (EcClientIdentity identity = identity(dir)) {
            for (int round = 0; round < 3; round++) {
                try (EchoServer server = EchoServer.start(serverContext, true);
                        Transport socket = connectTo(server);
                        TlsConnection tls = ClientHandshake.connect(socket, HOSTNAME,
                                CertificateTrust.of(trustStore), identity)) {
                    byte[] sent = ("round " + round).getBytes(StandardCharsets.US_ASCII);
                    tls.write(ByteBuffer.wrap(sent));
                    assertArrayEquals(sent, readExactly(tls, sent.length), "round " + round);
                }
            }
        }
    }

    /** The P-256 class keeps its word: a P-384 certificate is not taken for one. */
    @Test
    void theP256ClassStillRefusesAP384Certificate(@TempDir Path dir) throws Exception {
        Path key = dir.resolve("client.key");
        Files.writeString(key, pem(client));
        Path chain = dir.resolve("client.crt");
        Files.writeString(chain, certificatePem(client.certificate()));
        assertThrows(RuntimeException.class, () -> new P256ClientIdentity(chain, file(key)));
    }

    /** A P-256 key with a P-384 certificate: the curves disagree, and it says so. */
    @Test
    void aKeyOfTheWrongCurveIsRefusedAtLoad(@TempDir Path dir) throws Exception {
        TestCertificates.Issued p256 = certificates.issueEc("other",
                "ku:c=digitalSignature", "eku=clientAuth");
        Path key = dir.resolve("other.key");
        Files.writeString(key, pem(p256));
        Path chain = dir.resolve("client.crt");
        Files.writeString(chain, certificatePem(client.certificate()));
        RuntimeException refused = assertThrows(RuntimeException.class,
                () -> new EcClientIdentity(chain, file(key)).close());
        assertTrue(refused.getMessage().contains("private key"), refused.getMessage());
    }

    private static EcClientIdentity identity(Path dir) throws Exception {
        Path key = dir.resolve("client.key");
        Files.writeString(key, pem(client));
        Path chain = dir.resolve("client.crt");
        Files.writeString(chain, certificatePem(client.certificate()));
        return new EcClientIdentity(chain, file(key));
    }

    /** The private key as PKCS#8 PEM - through the JCA, as a test fixture only. */
    private static String pem(TestCertificates.Issued issued) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(issued.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        String alias = issued.certificate().getSubjectX500Principal().getName()
                .replace("CN=", "");
        PrivateKey key = (PrivateKey) store.getKey(alias, TestCertificates.PASSWORD.toCharArray());
        return "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key.getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }

    private static String certificatePem(X509Certificate certificate) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'})
                        .encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    private static SecretProvider file(Path path) throws IOException {
        byte[] bytes = Files.readString(path).getBytes(StandardCharsets.US_ASCII);
        return new CallbackSecretProvider(bytes.length, target -> {
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
    }

    private static SSLContext contextFor(Path keystore, KeyStore trust) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        TrustManagerFactory trusts =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trusts.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), trusts.getTrustManagers(), null);
        return context;
    }

    private static Transport connectTo(EchoServer server) throws IOException {
        return SocketTransport.wrap(java.nio.channels.SocketChannel.open(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), server.port())));
    }

    private static byte[] readExactly(TlsConnection tls, int length) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(length);
        while (buffer.hasRemaining()) {
            if (tls.read(buffer) < 0) {
                throw new IOException("the connection closed after " + buffer.position()
                        + " of " + length + " bytes");
            }
        }
        return buffer.array();
    }
}
