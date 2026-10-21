package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
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
 * A record that does not authenticate, arriving while another thread writes.
 *
 * <p>The reading thread refuses the record and ends the connection. Before
 * 20.10.2026 it did so holding only the read lock: it sealed its alert under
 * the write key while the writing thread was sealing a record of its own - the
 * same sequence number, so the same AES-GCM nonce for two plaintexts - and then
 * freed the cipher state that writer was still encrypting with. That ended in
 * an {@code IllegalStateException} from a closed arena, or with the JVM dying
 * in OpenSSL. Now the alert waits for nobody: it goes out only if the write
 * lock is free, and the memory is freed once the writer has let go.
 *
 * <p>The bad record is made by a proxy in the middle that flips the last byte
 * of the server's twentieth encrypted record - one bit of its tag - which is
 * all an attacker on the network needs to do to get here.
 *
 * <p>Server and proxy run on platform threads. On virtual threads, on
 * Windows, the proxy's pumps and the JSSE server stalled with full buffers
 * on both sides, and every round timed out with both seclume threads
 * waiting correctly in their socket calls - a hang in the harness, not in
 * the code under test.
 */
@Timeout(300)
@org.junit.jupiter.api.parallel.Isolated
class AbortWhileWritingTest {

    private static final int ROUNDS = 100;
    private static final int TAMPERED_RECORD = 20;

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

    @Test
    void aBadRecordDuringAWriteEndsTheConnectionTls13() throws Exception {
        refuseWhileWriting("TLSv1.3");
    }

    @Test
    void aBadRecordDuringAWriteEndsTheConnectionTls12() throws Exception {
        refuseWhileWriting("TLSv1.2");
    }

    private static void refuseWhileWriting(String protocol) throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
             ServerSocket proxy = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            listener.setEnabledProtocols(new String[] {protocol});
            daemon("server", () -> serve(listener));
            daemon("proxy", () -> tamper(proxy, listener.getLocalPort()));

            for (int round = 0; round < ROUNDS; round++) {
                SocketTransport transport = SocketTransport.connect("localhost",
                        proxy.getLocalPort(), 5000);
                TlsLayer tls = TlsLayers.start(TlsStack.SECLUME, transport, "localhost",
                        proxy.getLocalPort(), false);
                CountDownLatch writing = new CountDownLatch(1);
                AtomicReference<Throwable> writeEnded = new AtomicReference<>();
                AtomicReference<Throwable> readEnded = new AtomicReference<>();
                Thread writer = new Thread(() -> {
                    ByteBuffer chunk = ByteBuffer.allocateDirect(16 * 1024);
                    try {
                        while (true) {
                            chunk.clear();
                            tls.write(chunk);
                            writing.countDown();
                        }
                    } catch (Throwable e) {
                        writeEnded.set(e);
                    }
                }, "writer");
                writer.setDaemon(true);
                writer.start();
                assertTrue(writing.await(10, TimeUnit.SECONDS), "nothing could be written");
                Thread reader = new Thread(() -> {
                    ByteBuffer buffer = ByteBuffer.allocateDirect(64 * 1024);
                    try {
                        while (true) {
                            buffer.clear();
                            if (tls.read(buffer) < 0) {
                                return;
                            }
                        }
                    } catch (Throwable e) {
                        readEnded.set(e);
                    }
                }, "reader");
                reader.setDaemon(true);
                reader.start();

                reader.join(30_000);
                assertTrue(!reader.isAlive(), protocol + ": the read did not end at the bad record");
                writer.join(30_000);
                assertTrue(!writer.isAlive(), protocol + ": the write did not end with the connection");
                tls.close();

                Throwable read = readEnded.get();
                assertTrue(read instanceof IOException, protocol + ", round " + round
                        + ": the bad record ended the read with " + read);
                Throwable write = writeEnded.get();
                assertTrue(write instanceof IOException, protocol + ", round " + round
                        + ": the refused connection ended the write with " + write);
            }
        }
    }

    /** Sends records without end and reads whatever the client writes. */
    private static void serve(SSLServerSocket listener) {
        byte[] chunk = new byte[16 * 1024];
        while (!listener.isClosed()) {
            try {
                Socket socket = listener.accept();
                Thread.ofPlatform().daemon().start(() -> {
                    try (socket; OutputStream out = socket.getOutputStream()) {
                        InputStream in = socket.getInputStream();
                        Thread.ofPlatform().daemon().start(() -> drain(in));
                        while (true) {
                            out.write(chunk);
                        }
                    } catch (IOException gone) {
                        // the client went
                    }
                });
            } catch (IOException closed) {
                return;
            }
        }
    }

    /**
     * Passes both directions through, and flips the last byte of the server's
     * {@link #TAMPERED_RECORD}th encrypted record - the end of its tag.
     */
    private static void tamper(ServerSocket proxy, int serverPort) {
        while (!proxy.isClosed()) {
            try {
                Socket client = proxy.accept();
                Socket server = new Socket(InetAddress.getLoopbackAddress(), serverPort);
                Thread.ofPlatform().daemon().start(() -> pump(client, server));
                Thread.ofPlatform().daemon().start(() -> {
                    try (client; server) {
                        DataInputStream in = new DataInputStream(server.getInputStream());
                        OutputStream out = client.getOutputStream();
                        byte[] header = new byte[5];
                        int encrypted = 0;
                        while (true) {
                            in.readFully(header);
                            int length = ((header[3] & 0xff) << 8) | (header[4] & 0xff);
                            byte[] body = new byte[length];
                            in.readFully(body);
                            if (header[0] == 23 && ++encrypted == TAMPERED_RECORD && length > 0) {
                                body[length - 1] ^= 1;
                            }
                            out.write(header);
                            out.write(body);
                        }
                    } catch (IOException gone) {
                        // one side closed
                    }
                });
            } catch (IOException closed) {
                return;
            }
        }
    }

    private static void pump(Socket from, Socket to) {
        try {
            from.getInputStream().transferTo(to.getOutputStream());
        } catch (IOException gone) {
            // one side closed
        }
    }

    private static void drain(InputStream in) {
        byte[] sink = new byte[16 * 1024];
        try {
            while (in.read(sink) >= 0) {
                // what the client writes only has to be read
            }
        } catch (IOException gone) {
            // the client went
        }
    }

    private static void daemon(String name, Runnable body) {
        Thread thread = new Thread(body, name);
        thread.setDaemon(true);
        thread.start();
    }
}
