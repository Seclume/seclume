package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.sql.SQLInvalidAuthorizationSpecException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;

/**
 * The password itself - caching_sha2_password's full path - goes only to a
 * server that has proved who it is. Under the default tls=prefer the
 * certificate is not checked: a server in the middle that terminates TLS
 * itself and answers "full authentication required" was handed the password
 * in the clear. Against a fake server that does exactly that.
 */
@Timeout(120)
class CleartextPasswordTest {

    private static final String PASSWORD = "hunter2-hunter2";
    private static final byte[] SCRAMBLE = "abcdefghijklmnopqrst".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    static Path directory;
    private static SSLContext serverContext;
    private static String serverPin;

    @BeforeAll
    static void aSelfMadeCertificate() throws Exception {
        Path store = directory.resolve("server.p12");
        Process keytool = new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "server", "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=fake-mysql", "-ext", "san=ip:127.0.0.1", "-validity", "2",
                "-storetype", "PKCS12", "-keystore", store.toString(),
                "-storepass", "fake-mysql", "-keypass", "fake-mysql")
                .redirectErrorStream(true).start();
        keytool.getInputStream().readAllBytes();
        assertTrue(keytool.waitFor(60, TimeUnit.SECONDS) && keytool.exitValue() == 0,
                "keytool failed");
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(store)) {
            keys.load(in, "fake-mysql".toCharArray());
        }
        serverPin = TrustChoice.pinOf((X509Certificate) keys.getCertificate("server"));
        KeyManagerFactory factory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keys, "fake-mysql".toCharArray());
        serverContext = SSLContext.getInstance("TLSv1.3");
        serverContext.init(factory.getKeyManagers(), null, null);
    }

    /**
     * A MySQL that offers TLS with its own certificate, takes the login inside
     * it, asks for caching_sha2_password's full path and returns whatever
     * arrives next - the password, or null when the client sent nothing.
     */
    private static CompletableFuture<byte[]> serve(ServerSocket listener) {
        return CompletableFuture.supplyAsync(() -> {
            try (Socket plain = listener.accept()) {
                plain.setSoTimeout(30_000);
                OutputStream out = plain.getOutputStream();
                sendHandshake(out);
                readPacket(plain.getInputStream());               // the SSL request
                SSLSocket tls = (SSLSocket) serverContext.getSocketFactory()
                        .createSocket(plain, "127.0.0.1", plain.getPort(), true);
                tls.setUseClientMode(false);
                tls.startHandshake();
                InputStream in = tls.getInputStream();
                OutputStream secure = tls.getOutputStream();
                readPacket(in);                                   // the login, a hash
                writePacket(secure, new byte[] {0x01, 0x04}, 3);  // full authentication
                byte[] next;
                try {
                    next = readPacket(in);
                } catch (IOException closed) {
                    return null;
                }
                writePacket(secure, new byte[] {(byte) 0xff, 0x15, 0x04, '#', '2', '8', '0', '0',
                        '0', 'n', 'o'}, 5);
                return next;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }

    private static void sendHandshake(OutputStream out) throws IOException {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        payload.write(10);
        payload.writeBytes("8.4.0-fake\0".getBytes(StandardCharsets.US_ASCII));
        writeInt(payload, 7, 4);
        payload.write(SCRAMBLE, 0, 8);
        payload.write(0);
        int lower = MyCapabilities.PROTOCOL_41 | MyCapabilities.SECURE_CONNECTION
                | MyCapabilities.CONNECT_WITH_DB | MyCapabilities.TRANSACTIONS
                | MyCapabilities.SSL;
        writeInt(payload, lower & 0xffff, 2);
        payload.write(45);
        writeInt(payload, 2, 2);
        int upper = MyCapabilities.PLUGIN_AUTH | MyCapabilities.PLUGIN_AUTH_LENENC_CLIENT_DATA
                | MyCapabilities.DEPRECATE_EOF | MyCapabilities.CONNECT_ATTRS
                | MyCapabilities.MULTI_RESULTS;
        writeInt(payload, upper >>> 16, 2);
        payload.write(21);
        payload.write(new byte[10]);
        payload.write(SCRAMBLE, 8, 12);
        payload.write(0);
        payload.writeBytes("caching_sha2_password\0".getBytes(StandardCharsets.US_ASCII));
        writePacket(out, payload.toByteArray(), 0);
    }

    private static void writePacket(OutputStream out, byte[] payload, int sequence)
            throws IOException {
        out.write(payload.length & 0xff);
        out.write((payload.length >>> 8) & 0xff);
        out.write((payload.length >>> 16) & 0xff);
        out.write(sequence & 0xff);
        out.write(payload);
        out.flush();
    }

    private static byte[] readPacket(InputStream in) throws IOException {
        DataInputStream data = new DataInputStream(in);
        int length = data.readUnsignedByte() | data.readUnsignedByte() << 8
                | data.readUnsignedByte() << 16;
        data.readUnsignedByte();
        byte[] payload = new byte[length];
        data.readFully(payload);
        return payload;
    }

    private static void writeInt(ByteArrayOutputStream out, long value, int length) {
        for (int i = 0; i < length; i++) {
            out.write((int) ((value >>> (8 * i)) & 0xff));
        }
    }

    private static SecretProvider password() {
        return new CallbackSecretProvider(64, target -> {
            byte[] bytes = PASSWORD.getBytes(StandardCharsets.US_ASCII);
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
    }

    private static MySession.Settings settings(int port, boolean allowCleartext) {
        return new MySession.Settings("127.0.0.1", port, "testdb", "app", password(), "seclume",
                10_000, false, HostList.of("127.0.0.1", port), ResultLimit.NONE,
                TlsMode.PREFER, TlsStack.SECLUME, null, true, java.util.Set.of(),
                allowCleartext);
    }

    private static ServerSocket listener() throws IOException {
        return new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
    }

    @Test
    void notOverTlsThatCheckedNothing() throws Exception {
        try (ServerSocket listener = listener()) {
            CompletableFuture<byte[]> received = serve(listener);
            SQLInvalidAuthorizationSpecException refused = assertThrows(
                    SQLInvalidAuthorizationSpecException.class,
                    () -> MySession.open(settings(listener.getLocalPort(), false)).close());
            assertEquals("28000", refused.getSQLState());
            assertTrue(refused.getMessage().contains("caching_sha2_password full authentication"),
                    refused.getMessage());
            assertTrue(refused.getMessage().contains("tls=prefer"), refused.getMessage());
            assertNull(received.get(30, TimeUnit.SECONDS), "something went to the server");
        }
    }

    @Test
    void toThePinnedKey() throws Exception {
        try (ServerSocket listener = listener()) {
            CompletableFuture<byte[]> received = serve(listener);
            TrustChoice.Choice pin = TrustChoice.of("jdbc:x://h/db?tlsPin=" + serverPin, null);
            assertThrows(SQLException.class, () -> TrustChoice.using(pin,
                    () -> MySession.open(settings(listener.getLocalPort(), false))).close());
            assertArrayEquals((PASSWORD + "\0").getBytes(StandardCharsets.US_ASCII),
                    received.get(30, TimeUnit.SECONDS), "the pinned server got no password");
        }
    }

    @Test
    void withTheOptOut() throws Exception {
        try (ServerSocket listener = listener()) {
            CompletableFuture<byte[]> received = serve(listener);
            assertThrows(SQLException.class,
                    () -> MySession.open(settings(listener.getLocalPort(), true)).close());
            assertArrayEquals((PASSWORD + "\0").getBytes(StandardCharsets.US_ASCII),
                    received.get(30, TimeUnit.SECONDS));
        }
    }
}
