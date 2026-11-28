package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.LiveTls;
import space.seclume.internal.SocketTransport;
import space.seclume.internal.Transport;

/**
 * The count of open TLS connections is what a checkpoint refuses on: one
 * counted too many keeps every checkpoint refused, one too few lets an image
 * be taken with a session key in it. A hundred rounds - closed properly,
 * aborted with the socket gone under the connection, and handshakes that
 * fail on the server's name - and the count is where it started.
 */
@Timeout(300)
@Isolated
class LiveTlsCountTest {

    private static final String HOSTNAME = "db.example.com";

    private static SSLContext serverContext;
    private static CertificateTrust trust;

    @BeforeAll
    static void aServer() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        TestCertificates certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issue("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (java.io.InputStream in = java.nio.file.Files.newInputStream(server.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        serverContext = SSLContext.getInstance("TLSv1.3");
        serverContext.init(keys.getKeyManagers(), null, null);
        trust = CertificateTrust.of(certificates.trustStore());
    }

    private static Transport dial(EchoServer server) throws IOException {
        return SocketTransport.wrap(java.nio.channels.SocketChannel.open(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), server.port())));
    }

    /**
     * While a checkpoint holds, a handshake begun in another thread waits -
     * its key shares and traffic secrets would otherwise be made between the
     * barrier and the image - and completes once the hold is released.
     */
    @Test
    void aHandshakeWaitsWhileACheckpointHolds() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext)) {
            Transport socket = dial(server);
            java.util.concurrent.CompletableFuture<TlsConnection> handshake;
            space.seclume.internal.Checkpoint.hold();
            try {
                handshake = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                    try {
                        return ClientHandshake.connect(socket, HOSTNAME, trust);
                    } catch (IOException e) {
                        throw new java.io.UncheckedIOException(e);
                    }
                });
                assertThrows(java.util.concurrent.TimeoutException.class,
                        () -> handshake.get(500, java.util.concurrent.TimeUnit.MILLISECONDS),
                        "a handshake went through while the checkpoint held");
            } finally {
                space.seclume.internal.Checkpoint.release();
            }
            try (TlsConnection connection = handshake.get(30,
                    java.util.concurrent.TimeUnit.SECONDS)) {
                org.junit.jupiter.api.Assertions.assertNotNull(connection);
            }
        }
    }

    @Test
    void aHundredConnectionsLeaveTheCountWhereItWas() throws Exception {
        int before = LiveTls.count();
        for (int round = 0; round < 100; round++) {
            try (EchoServer server = EchoServer.start(serverContext)) {
                Transport socket = dial(server);
                switch (round % 3) {
                    case 0 -> {
                        TlsConnection connection = ClientHandshake.connect(socket, HOSTNAME, trust);
                        assertEquals(before + 1, LiveTls.count(), "round " + round);
                        connection.close();
                    }
                    case 1 -> {
                        // Aborted: the socket goes, then the connection is closed over it.
                        TlsConnection connection = ClientHandshake.connect(socket, HOSTNAME, trust);
                        socket.close();
                        try {
                            connection.write(ByteBuffer.wrap(new byte[] {1}));
                        } catch (IOException gone) {
                            // what a dead socket answers
                        }
                        connection.close();
                    }
                    default -> {
                        // The certificate is not for this name: the handshake fails.
                        assertThrows(IOException.class,
                                () -> ClientHandshake.connect(socket, "other.example.com", trust)
                                        .close());
                        socket.close();
                    }
                }
            }
            assertEquals(before, LiveTls.count(), "after round " + round);
        }
    }
}
