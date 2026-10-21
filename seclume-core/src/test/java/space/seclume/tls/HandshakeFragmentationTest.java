package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.jdbc.TlsStack;

/**
 * The server's handshake messages cut into small records (RFC 5246 section
 * 6.2.1, RFC 8446 section 5.1: a handshake message may span several records,
 * and several may share one). A proxy in the middle re-cuts every record in
 * the clear the server sends - ServerHello, and in TLS 1.2 Certificate,
 * ServerKeyExchange and ServerHelloDone too - into pieces of a few bytes;
 * TLS-Anvil's scanner does the same with 50.
 */
@Timeout(60)
class HandshakeFragmentationTest {

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

    @ParameterizedTest(name = "{0}, pieces of {1}")
    @CsvSource({"TLSv1.2, 50", "TLSv1.2, 1", "TLSv1.3, 50", "TLSv1.3, 1"})
    void aHandshakeInSmallRecordsCompletes(String protocol, int piece) throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
             ServerSocket proxy = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            listener.setEnabledProtocols(new String[] {protocol});
            daemon(() -> echo(listener));
            AtomicInteger pieces = new AtomicInteger();
            daemon(() -> cut(proxy, listener.getLocalPort(), piece, pieces));

            SocketTransport transport = SocketTransport.connect("localhost",
                    proxy.getLocalPort(), 5000);
            TlsLayer tls = TlsLayers.start(TlsStack.SECLUME, transport, "localhost",
                    proxy.getLocalPort(), false);
            try {
                ByteBuffer out = ByteBuffer.allocateDirect(5);
                out.put(new byte[] {'h', 'e', 'l', 'l', 'o'}).flip();
                tls.write(out);
                ByteBuffer in = ByteBuffer.allocateDirect(5);
                while (in.hasRemaining()) {
                    if (tls.read(in) < 0) {
                        break;
                    }
                }
                in.flip();
                byte[] echoed = new byte[in.remaining()];
                in.get(echoed);
                assertEquals("hello", new String(echoed, java.nio.charset.StandardCharsets.US_ASCII));
                // The server's first flight went out in many records, not a few.
                assertTrue(pieces.get() > 2, "only " + pieces.get() + " pieces were sent");
            } finally {
                tls.close();
            }
        }
    }

    /** Sends back what it reads. */
    private static void echo(SSLServerSocket listener) {
        while (!listener.isClosed()) {
            try {
                Socket socket = listener.accept();
                daemon(() -> {
                    try (socket) {
                        socket.getInputStream().transferTo(socket.getOutputStream());
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
     * Passes the client's bytes through and re-cuts the server's records in
     * the clear - handshake (22) and alert (21) - into pieces of {@code piece}
     * bytes, until the first ChangeCipherSpec or encrypted record; from then
     * on everything passes as it is.
     */
    private static void cut(ServerSocket proxy, int serverPort, int piece,
                            AtomicInteger pieces) {
        while (!proxy.isClosed()) {
            try {
                Socket client = proxy.accept();
                Socket server = new Socket(InetAddress.getLoopbackAddress(), serverPort);
                daemon(() -> pump(client, server));
                daemon(() -> {
                    try (client; server) {
                        DataInputStream in = new DataInputStream(server.getInputStream());
                        OutputStream out = client.getOutputStream();
                        byte[] header = new byte[5];
                        boolean clear = true;
                        while (true) {
                            in.readFully(header);
                            int length = ((header[3] & 0xff) << 8) | (header[4] & 0xff);
                            byte[] body = new byte[length];
                            in.readFully(body);
                            clear &= header[0] == 22;
                            if (!clear) {
                                out.write(header);
                                out.write(body);
                                out.flush();
                                continue;
                            }
                            for (int at = 0; at < length; at += piece) {
                                int size = Math.min(piece, length - at);
                                out.write(new byte[] {header[0], header[1], header[2],
                                        (byte) (size >> 8), (byte) size});
                                out.write(body, at, size);
                                pieces.incrementAndGet();
                            }
                            out.flush();
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

    private static void daemon(Runnable body) {
        Thread thread = new Thread(body);
        thread.setDaemon(true);
        thread.start();
    }
}
