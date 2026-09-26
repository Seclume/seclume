package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;

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

/**
 * A client certificate rotated on disk is used by the next handshake, with no
 * restart - and a rotation that is only half done breaks nothing.
 *
 * <p><b>How "the server saw the new certificate" is shown.</b> Two
 * authorities. The old client certificate comes from the first, the new one
 * from the second, and the server trusts <b>only the second</b> - the state a
 * database is in after its operators moved client authentication to a new CA.
 * A handshake that succeeds can therefore only have presented the new
 * certificate, and one that fails the old. No introspection of the server is
 * needed, and none would be as convincing: the server's own verdict is the
 * evidence.
 *
 * <p>The identity is built the way a deployment builds it - from
 * {@code clientCert} and {@code clientKey-*} settings through
 * {@link ClientIdentities} - so what is tested is the configured path and not
 * a class nobody instantiates directly.
 */
@Timeout(120)
class CertificateReloadTest {

    private static final String HOSTNAME = "db.example.com";

    private static TestCertificates oldAuthority;
    private static TestCertificates newAuthority;
    private static TestCertificates.Issued oldClient;
    private static TestCertificates.Issued newClient;
    private static SSLContext serverContext;
    private static KeyStore serverTrust;

    @BeforeAll
    static void twoAuthorities() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        Assumptions.assumeTrue(P256Signer.available(),
                "off-heap P-256 signing needs Windows or 64-bit Linux with libcrypto.so.3");

        oldAuthority = TestCertificates.generate();
        newAuthority = TestCertificates.generate();
        oldClient = oldAuthority.issueEc("client-old", "ku:c=digitalSignature",
                "eku=clientAuth");
        newClient = newAuthority.issueEc("client-new", "ku:c=digitalSignature",
                "eku=clientAuth");
        TestCertificates.Issued server = newAuthority.issue("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        // Client certificates are checked against the new authority alone.
        serverTrust = newAuthority.trustStore();
        serverContext = contextFor(server.keystore(), serverTrust);
    }

    @AfterAll
    static void removeTheAuthorities() throws IOException {
        if (oldAuthority != null) {
            oldAuthority.close();
        }
        if (newAuthority != null) {
            newAuthority.close();
        }
    }

    @Test
    void aRotatedCertificateIsUsedByTheNextHandshake(@TempDir Path dir) throws Exception {
        Path certificate = dir.resolve("client.crt");
        Path key = dir.resolve("client.key");
        write(certificate, key, oldClient, oldClient);

        try (ClientIdentity identity = ClientIdentities.of(settings(certificate, key))) {
            ReloadingClientIdentity reloading =
                    assertInstanceOf(ReloadingClientIdentity.class, identity,
                            "a configured identity does not follow its file");

            // Before: the old certificate is presented, and refused.
            assertThrows(IOException.class, () -> handshake(identity),
                    "the server accepted a certificate from an authority it does not trust - "
                            + "then this test proves nothing about which one was sent");

            // The rotation, as a deployment does it: both files replaced.
            write(certificate, key, newClient, newClient);

            // After: no restart, no new identity object - and accepted.
            handshake(identity);
            assertEquals(1, reloading.reloads(), "the new certificate was not taken up");
            assertArrayEquals(newClient.certificate().getEncoded(),
                    identity.forHandshake().chain().get(0));
        }
    }

    /**
     * The certificate lands before its key - and nothing breaks.
     *
     * <p>Rotations are rarely atomic. For a moment the new certificate sits
     * next to the old key, a pair that cannot sign for each other; the load is
     * refused, and the identity that worked must go on working rather than
     * turning a half-finished rotation into an outage. Here "working" is
     * shown the other way round from the test above: the server trusts the
     * old authority, so the old identity succeeding is the proof it was kept.
     */
    @Test
    void aHalfFinishedRotationKeepsTheIdentityThatWorks(@TempDir Path dir) throws Exception {
        // The pause before a refused certificate is tried again, shortened: five
        // seconds of waiting were half of this module's test time.
        ReloadingClientIdentity.retryMillis = 300;
        SSLContext oldServer = contextFor(
                oldAuthority.issue("server-old", "san=dns:" + HOSTNAME,
                        "ku:c=digitalSignature", "eku=serverAuth").keystore(),
                oldAuthority.trustStore());
        Path certificate = dir.resolve("client.crt");
        Path key = dir.resolve("client.key");
        write(certificate, key, oldClient, oldClient);

        try (ClientIdentity identity = ClientIdentities.of(settings(certificate, key))) {
            ReloadingClientIdentity reloading = (ReloadingClientIdentity) identity;
            handshake(identity, oldServer, oldAuthority.trustStore());

            // Half a rotation: the new certificate, the old key.
            Files.writeString(certificate, certificatePem(newClient.certificate()));

            handshake(identity, oldServer, oldAuthority.trustStore());
            assertEquals(0, reloading.reloads(),
                    "a certificate that does not match its key was taken up");
            assertArrayEquals(oldClient.certificate().getEncoded(),
                    identity.forHandshake().chain().get(0),
                    "the working identity was given up for one that cannot sign");

            // The key follows. After the pause for a refused certificate the
            // pair loads.
            Files.writeString(key, pem(newClient));
            Thread.sleep(ReloadingClientIdentity.retryMillis + 200);
            handshake(identity);
            assertEquals(1, reloading.reloads());
        } finally {
            ReloadingClientIdentity.retryMillis = ReloadingClientIdentity.RETRY_MILLIS;
        }
    }

    /**
     * A handshake that began with the old version finishes with it.
     *
     * <p>The version handed to a handshake has to go on signing after a
     * rotation replaced it - otherwise a handshake in flight at the moment of
     * the rotation would send one certificate and fail to sign for it. It is
     * released later, after a grace period, or at once when the whole
     * identity is closed.
     */
    @Test
    void theVersionAHandshakeHoldsStaysUsableAcrossARotation(@TempDir Path dir)
            throws Exception {
        Path certificate = dir.resolve("client.crt");
        Path key = dir.resolve("client.key");
        write(certificate, key, oldClient, oldClient);

        ClientIdentity identity = ClientIdentities.of(settings(certificate, key));
        ClientIdentity inFlight = identity.forHandshake();

        write(certificate, key, newClient, newClient);
        ClientIdentity next = identity.forHandshake();

        assertTrue(inFlight != next, "the rotation was not taken up");
        byte[] signature = inFlight.sign("the transcript".getBytes(StandardCharsets.US_ASCII));
        assertTrue(signature.length > 0, "the version in flight was closed under it");

        identity.close();
        assertThrows(IllegalStateException.class,
                () -> inFlight.sign("after".getBytes(StandardCharsets.US_ASCII)),
                "closing the identity left an old key resident in native memory");
    }

    // ------------------------------------------------------------- fixtures --

    private static Map<String, String> settings(Path certificate, Path key) {
        return Map.of(
                ClientIdentities.CERTIFICATE, certificate.toString(),
                ClientIdentities.KEY_PREFIX + "provider", "file",
                ClientIdentities.KEY_PREFIX + "path", key.toString());
    }

    private static void write(Path certificate, Path key, TestCertificates.Issued chain,
            TestCertificates.Issued keyOf) throws Exception {
        Files.writeString(certificate, certificatePem(chain.certificate()));
        Files.writeString(key, pem(keyOf));
    }

    private static void handshake(ClientIdentity identity) throws Exception {
        handshake(identity, serverContext, serverTrust);
    }

    private static void handshake(ClientIdentity identity, SSLContext server, KeyStore trust)
            throws Exception {
        try (EchoServer echo = EchoServer.start(server, true);
                Transport socket = connectTo(echo);
                TlsConnection tls = ClientHandshake.connect(socket, HOSTNAME,
                        CertificateTrust.of(trust), identity)) {
            // TLS 1.3 lets the server refuse a client certificate after the
            // client's Finished, so a handshake that returned is not yet an
            // accepted one. Data both ways is.
            byte[] sent = "select 1".getBytes(StandardCharsets.US_ASCII);
            tls.write(ByteBuffer.wrap(sent));
            ByteBuffer back = ByteBuffer.allocate(sent.length);
            while (back.hasRemaining()) {
                if (tls.read(back) < 0) {
                    throw new IOException("the server closed the connection - it refused the "
                            + "client certificate");
                }
            }
            assertArrayEquals(sent, back.array());
        }
    }

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
}
