package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.crypto.P256Signer;
import space.seclume.internal.SocketTransport;
import space.seclume.internal.Transport;
import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * Mutual TLS, judged by a server that did not come from this repository.
 *
 * <p>The gap this closes is the one the library used to leave open without
 * saying so: the password was kept off the heap with some care, and the
 * private key authenticating the very same connection was handed to the JCA,
 * where nothing can wipe it. Whoever has that key does not need the password.
 *
 * <p>A JSSE server with {@code setNeedClientAuth(true)} is the right judge
 * here for the same reason it is in {@code ClientHandshakeTest}: it sends a
 * real CertificateRequest, it builds the transcript itself, and it verifies
 * the CertificateVerify against the certificate we sent. A signature over the
 * wrong transcript, a DER encoding that is a byte out, a Certificate message
 * with the wrong context - each one ends here as a refused handshake and not
 * as a test agreeing with itself.
 *
 * <p>The private key reaches seclume as a PEM file through an ordinary secret
 * provider, which is how it arrives in a deployment: a mounted file, a
 * Kubernetes secret, or - since it is only a provider - anything else.
 */
@Timeout(120)
class MutualTlsTest {

    private static final String HOSTNAME = "db.example.com";

    private static TestCertificates certificates;
    private static SSLContext serverContext;
    private static KeyStore trustStore;
    private static TestCertificates.Issued client;

    @BeforeAll
    static void startAnAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        Assumptions.assumeTrue(P256Signer.available(),
                "off-heap P-256 signing needs Windows or 64-bit Linux with libcrypto.so.3");

        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issue("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        client = certificates.issueEc("client",
                "ku:c=digitalSignature", "eku=clientAuth");
        trustStore = certificates.trustStore();
        serverContext = contextFor(server.keystore(), trustStore);
    }

    @AfterAll
    static void removeTheAuthority() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    // ------------------------------------------------------------ the case --

    @Test
    void jsseAcceptsOurClientCertificateAndDataGoesBothWays(@TempDir Path dir) throws Exception {
        try (ClientIdentity identity = identity(dir);
                EchoServer server = EchoServer.start(serverContext, true);
                Transport socket = connectTo(server);
                TlsConnection tls = ClientHandshake.connect(socket, HOSTNAME,
                        CertificateTrust.of(trustStore), identity)) {

            byte[] sent = "select 1".getBytes(StandardCharsets.US_ASCII);
            tls.write(ByteBuffer.wrap(sent));
            assertArrayEquals(sent, readExactly(tls, sent.length),
                    "the server verified our certificate and the connection carries data");
        }
    }

    /**
     * Two connections with one identity.
     *
     * <p>A pool opens many. The key is loaded once and stays in the provider,
     * so the second handshake must work with nothing reloaded - and must not
     * quietly reuse the first signature, which would be over the wrong
     * transcript and would be refused.
     */
    @Test
    void oneIdentitySignsForSeveralConnections(@TempDir Path dir) throws Exception {
        try (ClientIdentity identity = identity(dir)) {
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

    /**
     * Without an identity the server refuses - and we do not hang.
     *
     * <p>The negative control for the test above: it shows the server really
     * is demanding a certificate, so the passing case is passing for the
     * reason claimed. It also pins the behaviour down - an empty Certificate
     * message rather than silence or a client-side exception, which leaves
     * the decision where it belongs.
     */
    @Test
    void withoutAnIdentityTheServerRefuses() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext, true);
                Transport socket = connectTo(server)) {
            assertThrows(IOException.class, () -> {
                try (TlsConnection tls = ClientHandshake.connect(socket, HOSTNAME,
                        CertificateTrust.of(trustStore))) {
                    // The refusal may arrive as an alert during the handshake
                    // or on the first read, depending on how far the server
                    // gets before it looks at what we sent.
                    tls.write(ByteBuffer.wrap("select 1".getBytes(StandardCharsets.US_ASCII)));
                    readExactly(tls, 1);
                }
            });
            assertNotNull(server.failure(), "the server should have rejected the connection");
        }
    }

    /** A server that does not ask never sees the identity, and nothing breaks. */
    @Test
    void anIdentityIsNotForcedOnAServerThatDoesNotAsk(@TempDir Path dir) throws Exception {
        try (ClientIdentity identity = identity(dir);
                EchoServer server = EchoServer.start(serverContext, false);
                Transport socket = connectTo(server);
                TlsConnection tls = ClientHandshake.connect(socket, HOSTNAME,
                        CertificateTrust.of(trustStore), identity)) {

            byte[] sent = "no certificate wanted".getBytes(StandardCharsets.US_ASCII);
            tls.write(ByteBuffer.wrap(sent));
            assertArrayEquals(sent, readExactly(tls, sent.length));
        }
    }

    /**
     * Loading the identity costs no open secret scope, whatever happens.
     *
     * <p>The key file passes through native memory on its way into the
     * provider. A malformed one leaves through an exception, which is where a
     * wipe gets skipped - the same failure shape {@code WipeOnFailureTest}
     * covers for passwords, checked here for the other kind of secret.
     */
    @Test
    void abrokenKeyFileLeavesNothingOpen(@TempDir Path dir) throws Exception {
        long open = SecretScope.open();

        assertThrows(RuntimeException.class, () -> new P256ClientIdentity(
                List.of(client.certificate().getEncoded()),
                provider("-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n")));

        assertTrue(SecretScope.open() == open,
                "a rejected key file left a secret scope open");
    }

    /** An RSA client certificate is refused with a reason, not silently downgraded. */
    @Test
    void anRsaClientCertificateIsRefusedClearly(@TempDir Path dir) throws Exception {
        TestCertificates.Issued rsa = certificates.issue("rsa-client",
                "ku:c=digitalSignature", "eku=clientAuth");

        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> new P256ClientIdentity(List.of(rsa.certificate().getEncoded()),
                        provider(pem(rsa))));
        assertTrue(refused.getMessage().contains("P-256"), refused.getMessage());
    }

    // ------------------------------------------------------------- fixtures --

    /** The client identity as a deployment has it: a chain and a PEM key file. */
    private static ClientIdentity identity(Path dir) throws Exception {
        Path key = dir.resolve("client.key");
        Files.writeString(key, pem(client));
        Path chain = dir.resolve("client.crt");
        Files.writeString(chain, certificatePem(client.certificate()));
        return new P256ClientIdentity(chain, file(key));
    }

    /**
     * The private key as PKCS#8 PEM.
     *
     * <p>Through the JCA, because keytool cannot export a private key and this
     * is a test fixture: what matters is that the <b>production</b> path from
     * the file to the signature never makes an object of it.
     */
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

    /** A provider reading a file, the way a deployment would configure it. */
    private static SecretProvider file(Path path) throws IOException {
        return provider(Files.readString(path));
    }

    private static SecretProvider provider(String content) {
        byte[] bytes = content.getBytes(StandardCharsets.US_ASCII);
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

        SSLContext context = SSLContext.getInstance("TLSv1.3");
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
