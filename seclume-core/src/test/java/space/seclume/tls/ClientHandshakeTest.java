package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.Transport;

/**
 * The whole handshake, against JSSE, over loopback - and the direction of
 * that sentence is the point.
 *
 * <p>Everything else in this package is checked against recorded bytes:
 * {@code KeyScheduleTest}, {@code FinishedTest} and
 * {@code CertificateVerificationTest} all replay RFC 8448 and can only ever
 * confirm that we read a transcript the same way its authors wrote it. None
 * of them can catch the other half - whether what <em>we</em> produce is
 * accepted by somebody who did not write this code.
 *
 * <p>A JSSE server can. It parses our ClientHello, decrypts our records with
 * keys it derived independently, and above all <b>verifies our Finished</b>:
 * a transcript that differs from its own by a single byte, a traffic secret
 * derived one step out of order, a record sealed under the wrong key - each
 * of those ends here as a failed handshake rather than as a test that passes
 * for the wrong reason. Then data goes both ways through it.
 *
 * <p>No server outside this machine is involved, and the certificate
 * authority lives for the length of the run.
 */
@Timeout(120)
class ClientHandshakeTest {

    private static final String HOSTNAME = "db.example.com";

    private static TestCertificates certificates;
    private static SSLContext serverContext;
    private static KeyStore trustStore;

    @BeforeAll
    static void startAnAuthorityAndAServerIdentity() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issue("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        trustStore = certificates.trustStore();
        serverContext = contextPresenting(server.keystore());
    }

    @AfterAll
    static void removeTheAuthority() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    // ---- the handshake ----------------------------------------------------

    @Test
    void jsseAcceptsOurHandshakeAndDataGoesBothWays() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext);
                Transport socket = connectTo(server);
                TlsConnection tls = ClientHandshake.connect(socket, HOSTNAME,
                        CertificateTrust.of(trustStore))) {
            byte[] sent = "select 1".getBytes(StandardCharsets.US_ASCII);
            tls.write(ByteBuffer.wrap(sent));
            assertArrayEquals(sent, readExactly(tls, sent.length),
                    "what came back through our own record layer must be what went in");
        }
    }

    /**
     * More than one record's worth in each direction - 20 000 bytes against a
     * 16 384-byte limit, so the writing side has to split and the reading
     * side has to put the pieces together.
     */
    @Test
    void dataLargerThanOneRecordSurvivesBothWays() throws Exception {
        byte[] payload = new byte[20_000];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) (i * 31 + 7);
        }
        try (EchoServer server = EchoServer.start(serverContext);
                Transport socket = connectTo(server);
                TlsConnection tls = ClientHandshake.connect(socket, HOSTNAME,
                        CertificateTrust.of(trustStore))) {
            tls.write(ByteBuffer.wrap(payload));
            assertArrayEquals(payload, readExactly(tls, payload.length));
        }
    }

    // ---- what must not be accepted ---------------------------------------

    @Test
    void aCertificateForAnotherNameStopsTheHandshake() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext);
                Transport socket = connectTo(server)) {
            IOException refused = assertThrows(IOException.class,
                    () -> ClientHandshake.connect(socket, "other.example.com",
                            CertificateTrust.of(trustStore)));
            assertTrue(refused.getMessage().contains("other.example.com"),
                    "the reason has to name the host: " + refused.getMessage());
        }
    }

    @Test
    void anAuthorityTheMachineDoesNotKnowStopsTheHandshake() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext);
                Transport socket = connectTo(server)) {
            IOException refused = assertThrows(IOException.class,
                    () -> ClientHandshake.connect(socket, HOSTNAME,
                            CertificateTrust.ofDefaultTrustStore()));
            assertTrue(refused.getMessage().toLowerCase(java.util.Locale.ROOT).contains("refused")
                            || refused.getMessage().toLowerCase(java.util.Locale.ROOT)
                                    .contains("certificate"),
                    "the reason has to be the certificate: " + refused.getMessage());
        }
    }

    /**
     * The same server, the same wrong name, with authentication deliberately
     * off - it has to succeed. Without this the two tests above would also
     * pass if the handshake were broken for some entirely different reason.
     */
    @Test
    void theUnauthenticatedRouteStillCompletesTheHandshake() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext);
                Transport socket = connectTo(server);
                TlsConnection tls =
                        ClientHandshake.connectWithoutAuthenticating(socket, "other.example.com")) {
            byte[] sent = "still encrypted".getBytes(StandardCharsets.US_ASCII);
            tls.write(ByteBuffer.wrap(sent));
            assertArrayEquals(sent, readExactly(tls, sent.length));
        }
    }

    // ---- plumbing ---------------------------------------------------------

    private static Transport connectTo(EchoServer server) throws IOException {
        return SocketTransport.connect(java.net.InetAddress.getLoopbackAddress().getHostAddress(),
                server.port(), 10_000);
    }

    private static byte[] readExactly(TlsConnection tls, int count) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(count);
        while (buffer.hasRemaining()) {
            int read = tls.read(buffer);
            if (read < 0) {
                throw new IOException("the connection ended after "
                        + (count - buffer.remaining()) + " of " + count + " bytes");
            }
        }
        return buffer.array();
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
