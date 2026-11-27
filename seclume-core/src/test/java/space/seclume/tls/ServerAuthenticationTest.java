package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;

/**
 * The server's certificate decides, end to end, in both protocol versions:
 * a real handshake against a JSSE server whose certificate a test CA issued.
 * Trusting that CA, the right name connects - the control that keeps the
 * refusals honest. The wrong name, and the JVM's own trust store (which has
 * never heard of the CA), are refused. {@code CertificateTrustTest} checks the
 * validator itself; this checks that each handshake asks it.
 */
@Timeout(60)
// Counts the JVM's open TLS connections: another test's handshake beside it moves the count.
@org.junit.jupiter.api.parallel.Isolated
class ServerAuthenticationTest {

    private static TestCertificates certificates;
    private static SSLContext serverContext;

    @TempDir
    static Path directory;

    private static Path caFile;
    private static String serverPin;

    @BeforeAll
    static void startAnAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issue("server",
                "san=dns:localhost", "ku:c=digitalSignature", "eku=serverAuth");
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(server.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        serverPin = TrustChoice.pinOf((java.security.cert.X509Certificate) store.getCertificate(
                Collections.list(store.aliases()).get(0)));
        serverContext = SSLContext.getInstance("TLS");
        serverContext.init(keys.getKeyManagers(), null, null);

        KeyStore anchors = certificates.trustStore();
        StringBuilder pem = new StringBuilder();
        for (String alias : Collections.list(anchors.aliases())) {
            Certificate ca = anchors.getCertificate(alias);
            pem.append("-----BEGIN CERTIFICATE-----\n")
                    .append(Base64.getMimeEncoder(64, new byte[] {'\n'})
                            .encodeToString(ca.getEncoded()))
                    .append("\n-----END CERTIFICATE-----\n");
        }
        caFile = directory.resolve("ca.pem");
        Files.writeString(caFile, pem);
    }

    @AfterAll
    static void removeTheAuthority() throws Exception {
        if (certificates != null) {
            certificates.close();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void theTrustedCertificateForTheRightNameConnects(String protocol) throws Exception {
        try (SSLServerSocket listener = listen(protocol)) {
            TlsLayer tls = handshake(listener, "localhost", true);
            tls.close();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void theTrustedCertificateForAnotherNameIsRefused(String protocol) throws Exception {
        try (SSLServerSocket listener = listen(protocol)) {
            IOException refused = assertThrows(IOException.class,
                    () -> handshake(listener, "db.example.com", true).close());
            assertTrue(String.valueOf(refused.getMessage()).contains("db.example.com"),
                    refused.getMessage());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void aCertificateFromAnUnknownAuthorityIsRefused(String protocol) throws Exception {
        try (SSLServerSocket listener = listen(protocol)) {
            assertThrows(IOException.class,
                    () -> handshake(listener, "localhost", false).close());
        }
    }

    /**
     * Whether the server was authenticated, as the layer reports it to
     * {@code Secured.serverAuthenticated}: a chain checked or a pin compared
     * is, a handshake that checked nothing (tls=prefer, require) is not - on
     * both stacks, so that a pool's grade cannot call an unchecked server safe.
     */
    @ParameterizedTest
    @ValueSource(strings = {"SECLUME", "JSSE"})
    void theLayerSaysWhetherTheServerWasAuthenticated(String stackName) throws Exception {
        TlsStack stack = TlsStack.valueOf(stackName);
        TrustChoice.Choice ca = TrustChoice.of(Map.of(TrustChoice.ROOT_CERT, caFile.toString()));
        TrustChoice.Choice pin = TrustChoice.of(Map.of(TrustChoice.PIN, serverPin));
        try (SSLServerSocket listener = listen("TLSv1.3")) {
            try (TlsLayer checked = handshake(listener, stack, ca, true)) {
                assertEquals(Boolean.TRUE, checked.serverAuthenticated(), "verify-full");
            }
            try (TlsLayer unchecked = handshake(listener, stack, null, false)) {
                assertEquals(Boolean.FALSE, unchecked.serverAuthenticated(), "require");
            }
            try (TlsLayer pinned = handshake(listener, stack, pin, false)) {
                assertEquals(Boolean.TRUE, pinned.serverAuthenticated(), "tlsPin");
            }
        }
    }

    /**
     * A checkpoint has to know the TLS connections still open: their traffic
     * keys are in native memory no SecretScope counts. A connection of the own
     * stack is counted from its handshake until it is closed.
     */
    @org.junit.jupiter.api.Test
    void anOpenConnectionIsCountedUntilItIsClosed() throws Exception {
        try (SSLServerSocket listener = listen("TLSv1.3")) {
            int before = space.seclume.internal.LiveTls.count();
            TlsLayer open = handshake(listener, TlsStack.SECLUME,
                    TrustChoice.of(Map.of(TrustChoice.ROOT_CERT, caFile.toString())), true);
            assertEquals(before + 1, space.seclume.internal.LiveTls.count());
            assertTrue(!space.seclume.internal.LiveTls.origins().isEmpty(),
                    "an open connection names who opened it");
            open.close();
            assertEquals(before, space.seclume.internal.LiveTls.count());
        }
    }

    private static TlsLayer handshake(SSLServerSocket listener, TlsStack stack,
            TrustChoice.Choice choice, boolean verify) throws Exception {
        int port = listener.getLocalPort();
        return TrustChoice.using(choice, () -> {
            try {
                SocketTransport transport = SocketTransport.connect("localhost", port, 5000);
                return TlsLayers.start(stack, transport, "localhost", port, verify);
            } catch (IOException e) {
                throw new SQLException(e);
            }
        });
    }

    private static SSLServerSocket listen(String protocol) throws IOException {
        SSLServerSocket listener = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        listener.setEnabledProtocols(new String[] {protocol});
        Thread server = new Thread(() -> {
            while (!listener.isClosed()) {
                try {
                    Socket accepted = listener.accept();
                    // Each in its own thread: one that waits on a connection
                    // the client left open holds up no other.
                    Thread.ofVirtual().start(() -> {
                        try (Socket socket = accepted) {
                            socket.getInputStream().read();    // runs the handshake, then waits
                        } catch (IOException ignored) {
                            // a refused handshake, or the client gone
                        }
                    });
                } catch (IOException ignored) {
                    // the listener closing
                }
            }
        });
        server.setDaemon(true);
        server.start();
        return listener;
    }

    /** A handshake to the listener under {@code host}; with or without the test CA trusted. */
    private static TlsLayer handshake(SSLServerSocket listener, String host, boolean trustTheCa)
            throws Exception {
        int port = listener.getLocalPort();
        TrustChoice.Choice choice = trustTheCa
                ? TrustChoice.of(Map.of(TrustChoice.ROOT_CERT, caFile.toString())) : null;
        try {
            return TrustChoice.using(choice, () -> {
                try {
                    SocketTransport transport = SocketTransport.connect("localhost", port, 5000);
                    return TlsLayers.start(TlsStack.SECLUME, transport, host, port, true);
                } catch (IOException e) {
                    throw new SQLException(e);
                }
            });
        } catch (SQLException wrapped) {
            if (wrapped.getCause() instanceof IOException io) {
                throw io;
            }
            throw wrapped;
        }
    }
}
