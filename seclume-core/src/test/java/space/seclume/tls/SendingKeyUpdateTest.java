package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.jdbc.TlsStack;

/**
 * The client never changed its sending key on its own: only a KeyUpdate the
 * server asked for did. RFC 8446 section 5.5 puts AES-GCM's limit at 2^24.5
 * full records under one key; a peer that never asked let the client go past
 * it. After 2^24 records the client sends a KeyUpdate of its own.
 */
@Timeout(60)
class SendingKeyUpdateTest {

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

    /** The TlsConnection somewhere inside the layer. */
    private static TlsConnection connectionOf(Object layer, int depth) throws Exception {
        if (layer instanceof TlsConnection connection) {
            return connection;
        }
        if (layer == null || depth == 0) {
            return null;
        }
        for (Class<?> type = layer.getClass(); type != null && type != Object.class;
                type = type.getSuperclass()) {
            for (java.lang.reflect.Field field : type.getDeclaredFields()) {
                if (field.getType().isPrimitive()
                        || java.lang.reflect.Modifier.isStatic(field.getModifiers())) {
                    continue;
                }
                try {
                    field.setAccessible(true);
                } catch (RuntimeException closedModule) {
                    continue;
                }
                TlsConnection found = connectionOf(field.get(layer), depth - 1);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static RecordStream records(TlsConnection connection) throws Exception {
        java.lang.reflect.Field records = TlsConnection.class.getDeclaredField("records");
        records.setAccessible(true);
        return (RecordStream) records.get(connection);
    }

    @Test
    void after2To24RecordsTheClientChangesItsKey() throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            listener.setEnabledProtocols(new String[] {"TLSv1.3"});
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
                TlsConnection connection = connectionOf(tls, 4);
                assertTrue(connection != null, "no TlsConnection in " + tls.getClass());
                RecordStream records = records(connection);
                RecordProtection before = records.writeProtection();
                // 2^24 real records would take minutes: this one connection's
                // limit is lowered to two more than it has sent.
                java.lang.reflect.Field limit = TlsConnection.class.getDeclaredField(
                        "keyUpdateAfter");
                limit.setAccessible(true);
                limit.setLong(connection, before.sequence() + 2);

                byte[] sent = new byte[40_000];                  // three records
                new Random(7).nextBytes(sent);
                ByteBuffer out = ByteBuffer.allocateDirect(sent.length).put(sent).flip();
                while (out.hasRemaining()) {
                    tls.write(out);
                }
                ByteBuffer in = ByteBuffer.allocateDirect(sent.length);
                while (in.hasRemaining()) {
                    assertTrue(tls.read(in) >= 0, "the server stopped reading");
                }
                byte[] received = new byte[sent.length];
                in.flip().get(received);
                assertArrayEquals(sent, received, "the server read on under the new key");
                assertNotSame(before, records.writeProtection(), "the sending key was kept");
                assertTrue(records.writeProtection().sequence() < 10,
                        "the new key starts its count again");
            } finally {
                tls.close();
            }
        }
    }
}
