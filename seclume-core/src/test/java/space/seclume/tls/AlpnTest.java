package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.Transport;
import space.seclume.internal.jdbc.TlsStack;

/**
 * Application protocol negotiation, on both stacks.
 *
 * <p>Here for one reason, and it is worth naming so that nobody later
 * mistakes this for a general ALPN feature: <b>TDS 8.0 requires it.</b> SQL
 * Server's strict encryption puts TLS around the whole connection from the
 * first byte, and the way the server tells that apart from anything else
 * that dialled port 1433 is the protocol name {@code tds/8.0}. Without ALPN
 * there is no TDS 8.0, without TDS 8.0 there is no TLS 1.3 on SQL Server, and
 * without that no client certificate whose key stays off the heap.
 *
 * <p>The case that matters most is the negative one. A server that ignores
 * ALPN, or does not have the protocol configured, leaves the client speaking
 * something the other end never agreed to - and the way that fails is not an
 * error but a <b>hang</b>, each side waiting for the other. Both stacks
 * therefore refuse, and both refusals are checked here, because a check on
 * only one of them would pass while the other quietly carried on.
 */
@Timeout(120)
class AlpnTest {

    private static final String HOSTNAME = "db.example.com";
    private static final String TDS8 = "tds/8.0";

    private static TestCertificates certificates;
    private static SSLContext serverContext;
    private static KeyStore trustStore;

    @BeforeAll
    static void startAnAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issue("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        trustStore = certificates.trustStore();

        KeyManagerFactory keys = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (java.io.InputStream in = java.nio.file.Files.newInputStream(server.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        TrustManagerFactory trust = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trust.init(trustStore);
        serverContext = SSLContext.getInstance("TLS");
        serverContext.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
    }

    @AfterAll
    static void removeTheAuthority() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    /** The own stack offers it, the server takes it, and data flows. */
    @Test
    void ourStackNegotiatesTheProtocol() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext, false, TDS8);
                Transport socket = connectTo(server);
                TlsLayer tls = TlsLayers.start(TlsStack.SECLUME, socket, HOSTNAME,
                        server.port(), false, null, TDS8)) {
            echo(tls);
        }
    }

    /** And so does the JDK's, because SQL Server has to work on either. */
    @Test
    void theJdkStackNegotiatesTheProtocol() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext, false, TDS8);
                Transport socket = connectTo(server);
                TlsLayer tls = TlsLayers.start(TlsStack.JSSE, socket, HOSTNAME,
                        server.port(), false, null, TDS8)) {
            echo(tls);
        }
    }

    /**
     * A server that selects nothing is refused - the case that would
     * otherwise hang.
     */
    @Test
    void ourStackRefusesAServerThatDoesNotSelectIt() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext, false, null);
                Transport socket = connectTo(server)) {
            IOException refused = assertThrows(IOException.class,
                    () -> TlsLayers.start(TlsStack.SECLUME, socket, HOSTNAME, server.port(),
                            false, null, TDS8));
            assertTrue(refused.getMessage().contains(TDS8), refused.getMessage());
        }
    }

    /** The same refusal on the other stack, by the same argument. */
    @Test
    void theJdkStackRefusesAServerThatDoesNotSelectIt() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext, false, null);
                Transport socket = connectTo(server)) {
            IOException refused = assertThrows(IOException.class,
                    () -> TlsLayers.start(TlsStack.JSSE, socket, HOSTNAME, server.port(),
                            false, null, TDS8));
            assertTrue(refused.getMessage().contains(TDS8), refused.getMessage());
        }
    }

    /**
     * Without ALPN nothing changes.
     *
     * <p>The regression guard for every other connection in the project: an
     * extension that is offered when nobody asked for it would be sent to
     * four databases that never wanted it.
     */
    @Test
    void withoutAnAlpnTheHandshakeIsWhatItAlwaysWas() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext, false, TDS8);
                Transport socket = connectTo(server);
                TlsLayer tls = TlsLayers.start(TlsStack.SECLUME, socket, HOSTNAME,
                        server.port(), false, null, null)) {
            echo(tls);
        }
    }

    // ------------------------------------------------------------- fixtures --

    private static Transport connectTo(EchoServer server) throws IOException {
        return SocketTransport.wrap(java.nio.channels.SocketChannel.open(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), server.port())));
    }

    private static void echo(TlsLayer tls) throws IOException {
        byte[] sent = "select 1".getBytes(StandardCharsets.US_ASCII);
        tls.write(ByteBuffer.wrap(sent));
        ByteBuffer back = ByteBuffer.allocate(sent.length);
        while (back.hasRemaining()) {
            if (tls.read(back) < 0) {
                throw new IOException("the connection closed after " + back.position()
                        + " of " + sent.length + " bytes");
            }
        }
        assertArrayEquals(sent, back.array());
    }
}
