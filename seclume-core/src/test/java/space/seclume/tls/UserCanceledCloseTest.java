package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.jdbc.TlsStack;

/**
 * A server that answers and closes at once - an HTTP/1.1 server with
 * {@code Connection: close}, say. The JDK's server then sends
 * {@code user_canceled} as a warning before its {@code close_notify}, which
 * RFC 8446 6.1 allows ("SHOULD be followed by a close_notify"). That is the
 * end of the stream, read after the answer - not a failure of it.
 */
@Timeout(60)
class UserCanceledCloseTest {

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
        serverContext = SSLContext.getInstance("TLSv1.3");
        serverContext.init(keys.getKeyManagers(), null, null);
    }

    @AfterAll
    static void removeTheAuthority() throws Exception {
        if (certificates != null) {
            certificates.close();
        }
    }

    @Test
    void anAnswerFollowedByAnImmediateCloseIsReadToAnOrdinaryEnd() throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            listener.setEnabledProtocols(new String[] {"TLSv1.3"});
            Thread server = new Thread(() -> {
                try (Socket socket = listener.accept()) {
                    InputStream in = socket.getInputStream();
                    while (in.read() != '\n') {
                        // the request line
                    }
                    OutputStream out = socket.getOutputStream();
                    out.write("the answer\n".getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                } catch (Exception ignored) {
                    // the test fails on the client side
                }
            }, "answer-and-close");
            server.setDaemon(true);
            server.start();

            try (SocketTransport transport = SocketTransport.connect("localhost",
                    listener.getLocalPort(), 5000);
                 TlsLayer tls = TlsLayers.start(TlsStack.SECLUME, transport, "localhost",
                         listener.getLocalPort(), false)) {
                tls.write(ByteBuffer.wrap("question\n".getBytes(StandardCharsets.US_ASCII)));
                ByteArrayOutputStream answer = new ByteArrayOutputStream();
                ByteBuffer buffer = ByteBuffer.allocate(256);
                int n;
                while ((n = tls.read(buffer.clear())) >= 0) {
                    answer.write(buffer.array(), 0, n);
                }
                assertEquals("the answer\n", answer.toString(StandardCharsets.US_ASCII));
                assertTrue(tls.read(buffer.clear()) < 0, "and the end stays the end");
            }
        }
    }
}
