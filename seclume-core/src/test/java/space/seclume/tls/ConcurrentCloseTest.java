package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

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
 * Closing on one thread while another is reading - as a client library's
 * reader thread does while the application closes, a connection pool evicts,
 * or {@code Connection.abort} runs. Before 27.09.2026 the close freed the
 * cipher state that the reader was decrypting with, and the JVM died in
 * OpenSSL (SIGSEGV in EVP_DecryptUpdate) - a crash, not an exception, so this
 * test failing means the test run itself does not finish.
 */
@Timeout(180)
class ConcurrentCloseTest {

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
    void closingWhileAnotherThreadReadsEndsTheReadNotTheJvm() throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            listener.setEnabledProtocols(new String[] {"TLSv1.3"});
            Thread server = new Thread(() -> {
                byte[] chunk = new byte[16 * 1024];
                while (!listener.isClosed()) {
                    try {
                        Socket socket = listener.accept();
                        Thread.ofVirtual().start(() -> {
                            try (socket; OutputStream out = socket.getOutputStream()) {
                                while (true) {
                                    out.write(chunk);           // records without end
                                }
                            } catch (IOException gone) {
                                // the client closed
                            }
                        });
                    } catch (IOException closed) {
                        return;
                    }
                }
            }, "streaming-server");
            server.setDaemon(true);
            server.start();

            for (int round = 0; round < 200; round++) {
                SocketTransport transport = SocketTransport.connect("localhost",
                        listener.getLocalPort(), 5000);
                TlsLayer tls = TlsLayers.start(TlsStack.SECLUME, transport, "localhost",
                        listener.getLocalPort(), false);
                CountDownLatch reading = new CountDownLatch(1);
                AtomicReference<Throwable> ended = new AtomicReference<>();
                Thread reader = new Thread(() -> {
                    ByteBuffer buffer = ByteBuffer.allocateDirect(64 * 1024);
                    try {
                        while (true) {
                            buffer.clear();
                            if (tls.read(buffer) < 0) {
                                return;
                            }
                            reading.countDown();
                        }
                    } catch (Throwable e) {
                        ended.set(e);
                    }
                }, "reader");
                reader.start();
                assertTrue(reading.await(10, TimeUnit.SECONDS), "no data arrived");
                Thread.sleep(round % 5);             // close at different points of a record
                tls.close();
                reader.join(10_000);
                assertTrue(!reader.isAlive(), "the read did not end after close");
                Throwable end = ended.get();
                assertTrue(end == null || end instanceof IOException,
                        "the read ended with " + end);
            }
        }
    }
}
