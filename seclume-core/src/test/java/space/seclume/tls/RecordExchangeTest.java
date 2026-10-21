package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.Random;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.jdbc.TlsStack;

/**
 * Many records, both ways, against JSSE: lengths around the one- and
 * two-byte boundaries of the record header and the additional data (255, 256,
 * 257), around the largest record (16384, 16385) and well past it, each
 * written, echoed and compared byte for byte. One record proves little - its
 * sequence number is zero, and a nonce or additional data built wrong from
 * zero bytes still matches.
 */
@Timeout(60)
class RecordExchangeTest {

    private static final int[] LENGTHS = {1, 2, 255, 256, 257, 1000, 4096, 16383, 16384,
        16385, 40_000, 3, 70_000, 17};

    private static TestCertificates certificates;
    private static SSLContext serverContext;

    @BeforeAll
    static void startAnAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issue("server",
                "san=dns:localhost", "ku:c=digitalSignature", "eku=serverAuth");
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = java.nio.file.Files.newInputStream(server.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        serverContext = SSLContext.getInstance("TLS");
        serverContext.init(keys.getKeyManagers(), null, null);
    }

    @AfterAll
    static void removeTheAuthority() throws Exception {
        if (certificates != null) {
            certificates.close();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void everyLengthComesBackAsItWent(String protocol) throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            listener.setEnabledProtocols(new String[] {protocol});
            Thread echo = new Thread(() -> {
                try (Socket socket = listener.accept()) {
                    socket.getInputStream().transferTo(socket.getOutputStream());
                } catch (IOException gone) {
                    // the client closed
                }
            });
            echo.setDaemon(true);
            echo.start();

            SocketTransport transport = SocketTransport.connect("localhost",
                    listener.getLocalPort(), 5000);
            TlsLayer tls = TlsLayers.start(TlsStack.SECLUME, transport, "localhost",
                    listener.getLocalPort(), false);
            try {
                Random random = new Random(0x7EC0DE);
                for (int length : LENGTHS) {
                    byte[] sent = new byte[length];
                    random.nextBytes(sent);
                    ByteBuffer out = ByteBuffer.allocateDirect(length).put(sent).flip();
                    while (out.hasRemaining()) {
                        tls.write(out);
                    }
                    ByteBuffer in = ByteBuffer.allocateDirect(length);
                    while (in.hasRemaining()) {
                        assertTrue(tls.read(in) >= 0, protocol + ": the echo ended early at "
                                + length + " bytes");
                    }
                    byte[] received = new byte[length];
                    in.flip().get(received);
                    assertArrayEquals(sent, received, protocol + ": " + length + " bytes");
                }
            } finally {
                tls.close();
            }
        }
    }
}
