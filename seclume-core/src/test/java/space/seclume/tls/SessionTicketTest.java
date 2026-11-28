package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.Transport;

/**
 * The client resumes nothing: a server's NewSessionTickets - JSSE sends them
 * after every TLS 1.3 handshake - are read past, the data behind them
 * arrives, and the next ClientHello to the same server offers no
 * pre_shared_key. A ticket kept would be key material outliving its
 * connection, and a resumption would skip the certificate check.
 */
@Timeout(120)
class SessionTicketTest {

    private static final String HOSTNAME = "db.example.com";
    private static final int PRE_SHARED_KEY = 41;
    private static final int EARLY_DATA = 42;

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

    /** What the client writes, kept; what it reads, passed on. */
    private static final class Recording implements Transport {
        private final Transport inner;
        private final ByteArrayOutputStream written = new ByteArrayOutputStream();

        Recording(Transport inner) {
            this.inner = inner;
        }

        @Override
        public int read(ByteBuffer into) throws IOException {
            return inner.read(into);
        }

        @Override
        public int write(ByteBuffer from) throws IOException {
            ByteBuffer copy = from.duplicate();
            int count = inner.write(from);
            byte[] bytes = new byte[count];
            copy.get(bytes);
            written.writeBytes(bytes);
            return count;
        }

        @Override
        public boolean isOpen() {
            return inner.isOpen();
        }

        @Override
        public void close() {
            inner.close();
        }
    }

    /** The extension types of the ClientHello at the start of {@code bytes}. */
    private static List<Integer> extensions(byte[] bytes) {
        ByteBuffer in = ByteBuffer.wrap(bytes);
        assertEquals(22, in.get(), "a handshake record");
        in.position(5);
        assertEquals(1, in.get(), "a ClientHello");
        in.position(in.position() + 3 + 2 + 32);
        in.position(in.position() + 1 + (in.get(in.position()) & 0xff));       // session id
        in.position(in.position() + 2 + (in.getShort(in.position()) & 0xffff)); // suites
        in.position(in.position() + 1 + (in.get(in.position()) & 0xff));       // compression
        int end = in.position() + 2 + (in.getShort() & 0xffff);
        List<Integer> types = new ArrayList<>();
        while (in.position() < end) {
            types.add(in.getShort() & 0xffff);
            in.position(in.position() + 2 + (in.getShort(in.position()) & 0xffff));
        }
        return types;
    }

    private static List<Integer> connectAndEcho() throws IOException {
        try (EchoServer server = EchoServer.start(serverContext)) {
            Recording socket = new Recording(SocketTransport.wrap(
                    java.nio.channels.SocketChannel.open(new InetSocketAddress(
                            InetAddress.getLoopbackAddress(), server.port()))));
            List<Integer> types = null;
            try (TlsConnection connection = ClientHandshake.connect(socket, HOSTNAME, trust)) {
                types = extensions(socket.written.toByteArray());
                byte[] sent = "after the tickets".getBytes(StandardCharsets.US_ASCII);
                connection.write(ByteBuffer.wrap(sent));
                ByteBuffer back = ByteBuffer.allocate(sent.length);
                while (back.hasRemaining()) {
                    if (connection.read(back) < 0) {
                        throw new IOException("the echo ended early");
                    }
                }
                assertArrayEquals(sent, back.array(), "the data behind the tickets");
            }
            return types;
        }
    }

    @Test
    void ticketsAreReadPastAndTheNextHelloOffersNoResumption() throws Exception {
        List<Integer> first = connectAndEcho();
        List<Integer> second = connectAndEcho();
        for (List<Integer> types : List.of(first, second)) {
            assertFalse(types.contains(PRE_SHARED_KEY), "a pre_shared_key was offered: " + types);
            assertFalse(types.contains(EARLY_DATA), "early data was offered: " + types);
        }
        assertEquals(first, second, "the second hello differs from the first: something was kept");
    }
}
