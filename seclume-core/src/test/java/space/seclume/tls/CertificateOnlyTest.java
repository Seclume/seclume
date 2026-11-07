package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.Transport;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;

/**
 * {@code seclume-verify --print-pin} connects without checking the
 * certificate, because the certificate is what it wants to see. It used to
 * carry on to the login - the password sent, over TLS that authenticated
 * nobody, to whoever answered. {@link TrustChoice#certificateOnly} ends the
 * connection with the handshake: the certificate comes back, and not one
 * byte of the protocol reaches the server.
 */
@Timeout(120)
class CertificateOnlyTest {

    private static final String HOSTNAME = "db.example.com";
    private static TestCertificates certificates;
    private static SSLContext serverContext;
    private static String serverPin;

    @BeforeAll
    static void aServerCertificate() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issue("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(server.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        serverContext = SSLContext.getInstance("TLSv1.3");
        serverContext.init(keys.getKeyManagers(), null, null);
        serverPin = TrustChoice.pinOf(server.certificate());
    }

    @AfterAll
    static void removeTheCertificates() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    /** A TLS server that counts what arrives after its handshake. */
    private static final class CountingServer implements AutoCloseable {
        final SSLServerSocket socket;
        final AtomicInteger received = new AtomicInteger();
        final AtomicBoolean handshook = new AtomicBoolean();
        final Thread thread;

        CountingServer() throws IOException {
            socket = (SSLServerSocket) serverContext.getServerSocketFactory()
                    .createServerSocket(0, 1, InetAddress.getLoopbackAddress());
            socket.setSoTimeout(60_000);
            thread = Thread.ofVirtual().start(() -> {
                try (SSLSocket accepted = (SSLSocket) socket.accept()) {
                    accepted.setSoTimeout(30_000);
                    accepted.startHandshake();
                    handshook.set(true);
                    InputStream in = accepted.getInputStream();
                    byte[] buffer = new byte[256];
                    int read;
                    while ((read = in.read(buffer)) > 0) {
                        received.addAndGet(read);
                    }
                } catch (IOException ended) {
                    // the client went away - which is what it should do
                }
            });
        }

        int port() {
            return socket.getLocalPort();
        }

        /** What arrived, once the connection is over. */
        int receivedWhenDone() throws InterruptedException {
            thread.join(java.time.Duration.ofSeconds(30));
            return received.get();
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    /** What a driver does: the handshake, then the login - here, the password itself. */
    private static TlsLayer handshakeThenLogin(TlsStack stack, int port, AtomicBoolean loggedIn)
            throws SQLException {
        try {
            Transport transport = SocketTransport.connect(
                    InetAddress.getLoopbackAddress().getHostAddress(), port, 10_000);
            TlsLayer layer;
            try {
                layer = TlsLayers.start(stack, transport, HOSTNAME, port, false);
            } catch (IOException | RuntimeException e) {
                transport.close();
                throw e;
            }
            loggedIn.set(true);
            layer.write(ByteBuffer.wrap("PASSWORD=hunter2".getBytes(StandardCharsets.US_ASCII)));
            return layer;
        } catch (IOException e) {
            throw new java.sql.SQLNonTransientConnectionException("TLS failed: " + e.getMessage(),
                    "08001", e);
        }
    }

    @ParameterizedTest
    @EnumSource(value = TlsStack.class, names = {"SECLUME", "JSSE"})
    void theCertificateComesBackAndNothingElseIsSent(TlsStack stack) throws Exception {
        AtomicBoolean loggedIn = new AtomicBoolean();
        try (CountingServer server = new CountingServer()) {
            X509Certificate presented = TrustChoice.certificateOnly(
                    () -> handshakeThenLogin(stack, server.port(), loggedIn));
            assertEquals(serverPin, TrustChoice.pinOf(presented));
            assertFalse(loggedIn.get(), "the connection went on past the handshake");
            assertEquals(0, server.receivedWhenDone(), "bytes reached the server after the handshake");
            assertTrue(server.handshook.get(), "the server finished its handshake");
        }
    }

    @ParameterizedTest
    @EnumSource(value = TlsStack.class, names = {"SECLUME", "JSSE"})
    void afterwardsAHandshakeOnThisThreadGoesOnAsAlways(TlsStack stack) throws Exception {
        try (CountingServer first = new CountingServer()) {
            TrustChoice.certificateOnly(() -> handshakeThenLogin(stack, first.port(),
                    new AtomicBoolean()));
        }
        AtomicBoolean loggedIn = new AtomicBoolean();
        try (CountingServer server = new CountingServer()) {
            TlsLayer layer = handshakeThenLogin(stack, server.port(), loggedIn);
            layer.close();
            assertTrue(loggedIn.get());
            assertEquals("PASSWORD=hunter2".length(), server.receivedWhenDone());
        }
    }

    @Test
    void aConnectionThatFailsBeforeAnyHandshakeIsTheCallersFailure() throws Exception {
        int closed;
        try (ServerSocket gone = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            closed = gone.getLocalPort();
        }
        int port = closed;
        assertThrows(SQLException.class, () -> TrustChoice.certificateOnly(
                () -> handshakeThenLogin(TlsStack.SECLUME, port, new AtomicBoolean())));
    }

    @Test
    void aConnectionWithoutTlsHasNoCertificate() throws Exception {
        AtomicBoolean closed = new AtomicBoolean();
        assertNull(TrustChoice.certificateOnly(() -> (AutoCloseable) () -> closed.set(true)));
        assertTrue(closed.get(), "what came back is closed, not left open");
    }
}
