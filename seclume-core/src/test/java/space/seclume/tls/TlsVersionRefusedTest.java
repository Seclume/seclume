package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.Transport;
import space.seclume.internal.jdbc.TlsStack;

/**
 * Which handshake failures say "this server needs the JDK's stack" - the
 * signal {@code tlsStack=auto} falls back on - and which do not.
 *
 * <p>The servers are the JDK's own, limited the way real ones are: TLS 1.2
 * only, as SQL Server before TDS 8.0 and Oracle 19c are; no group this client
 * offers; a listener that hangs up on the ClientHello. And one that speaks
 * TLS 1.3 perfectly well but whose certificate is not trusted, which must
 * fail as a certificate failure - falling back there would only fail again,
 * on the other stack, with the password one step closer to the heap.
 */
@Timeout(120)
class TlsVersionRefusedTest {

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

    /**
     * SQL Server's TDS 7.x, Oracle 19c, MySQL 5.7: TLS 1.2 and nothing newer -
     * reached on the own stack, with the same data going both ways.
     */
    @Test
    void aTls12ServerIsReachedOnTheOwnStack() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext,
                socket -> socket.setEnabledProtocols(new String[] {"TLSv1.2"}));
                Transport socket = SocketTransport.wrap(java.nio.channels.SocketChannel.open(
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), server.port())));
                space.seclume.internal.TlsLayer tls = TlsLayers.start(TlsStack.SECLUME, socket,
                        HOSTNAME, server.port(), false)) {
            String description = tls.description();
            assertTrue(description.startsWith("TLSv1.2 / TLS_ECDHE_")
                    && description.endsWith(" (seclume)"), description);
            byte[] sent = "a TLS 1.2 record, there and back".getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII);
            tls.write(java.nio.ByteBuffer.wrap(sent));
            java.nio.ByteBuffer back = java.nio.ByteBuffer.allocate(sent.length);
            while (back.hasRemaining()) {
                assertTrue(tls.read(back) >= 0, "the echo ended early");
            }
            assertArrayEquals(sent, back.array());
        }
    }

    /** Kept to TLS 1.3 ({@code -Dseclume.tls.tls12=false}), the same server refuses the version. */
    @Test
    void aTls12ServerRefusesTheVersionWhenOnlyThirteenIsOffered() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext,
                socket -> socket.setEnabledProtocols(new String[] {"TLSv1.2"}));
                Transport socket = SocketTransport.wrap(java.nio.channels.SocketChannel.open(
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), server.port())))) {
            assertThrows(TlsVersionRefused.class, () -> ClientHandshake.connect(socket, HOSTNAME,
                    null, null, null, ClientHello.Offer.TLS13).close());
        }
    }

    /** No group in common: the server cannot even ask for another key share. */
    @Test
    void aServerWithoutOurGroupsRefusesTheVersion() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext, socket -> {
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setNamedGroups(new String[] {"x448"});
            socket.setSSLParameters(parameters);
        })) {
            assertInstanceOf(TlsVersionRefused.class, ownStack(server.port(), false));
        }
    }

    /** What Schannel and some listeners do: read the ClientHello, say nothing, close. */
    @Test
    void aServerThatHangsUpRefusesTheVersion() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            java.util.concurrent.atomic.AtomicInteger firstByte =
                    new java.util.concurrent.atomic.AtomicInteger(-2);
            Thread server = Thread.ofVirtual().start(() -> {
                try (Socket accepted = listener.accept()) {
                    firstByte.set(accepted.getInputStream().read());
                } catch (IOException ignored) {
                    // the client's view is what is tested
                }
            });
            assertInstanceOf(TlsVersionRefused.class, ownStack(listener.getLocalPort(), false));
            server.join();
            assertEquals(22, firstByte.get(), "the server hung up on something else than a ClientHello");
        }
    }

    /** A TLS 1.3 server with a certificate nobody trusts: no fallback, a refusal. */
    @Test
    void anUntrustedCertificateIsNotAVersionRefusal() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext, socket -> { })) {
            IOException refused = ownStack(server.port(), true);
            assertFalse(refused instanceof TlsVersionRefused, refused.toString());
        }
    }

    private static IOException ownStack(int port, boolean verify) throws IOException {
        try (Transport socket = SocketTransport.wrap(java.nio.channels.SocketChannel.open(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), port)))) {
            return assertThrows(IOException.class, () -> TlsLayers.start(TlsStack.AUTO, socket,
                    HOSTNAME, port, verify).close());
        }
    }
}
