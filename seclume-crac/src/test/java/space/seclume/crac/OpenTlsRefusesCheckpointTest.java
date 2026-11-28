package space.seclume.crac;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.Checkpoint;
import space.seclume.internal.SocketTransport;
import space.seclume.tls.ClientHandshake;
import space.seclume.tls.TlsConnection;

/**
 * An application that holds a TLS connection of seclume's own stack - no
 * pool, nothing else - and checkpoints: its traffic keys would be in the
 * image. The checkpoint is refused, the refusal names the class that opened
 * the connection, and once it is closed the checkpoint goes through.
 */
@Timeout(120)
@Isolated
class OpenTlsRefusesCheckpointTest {

    private static final String PASSWORD = "changeit";

    private static SSLContext serverContext(Path directory) throws Exception {
        Path store = directory.resolve("server.p12");
        Path keytool = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name", "").startsWith("Windows") ? "keytool.exe" : "keytool");
        Assumptions.assumeTrue(Files.isExecutable(keytool), "no keytool in this JDK");
        Process made = new ProcessBuilder(keytool.toString(), "-genkeypair", "-alias", "server",
                "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=localhost",
                "-validity", "2", "-storetype", "PKCS12", "-keystore", store.toString(),
                "-storepass", PASSWORD, "-keypass", PASSWORD).redirectErrorStream(true).start();
        made.getInputStream().readAllBytes();
        assertTrue(made.waitFor(60, TimeUnit.SECONDS) && made.exitValue() == 0, "keytool failed");
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(store)) {
            keys.load(in, PASSWORD.toCharArray());
        }
        KeyManagerFactory factory = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keys, PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(factory.getKeyManagers(), null, null);
        return context;
    }

    @Test
    void anOpenConnectionRefusesTheCheckpointNamingWhoOpenedIt(@TempDir Path directory)
            throws Exception {
        SSLContext context = serverContext(directory);
        try (SSLServerSocket listener = (SSLServerSocket) context.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(30_000);
            Thread server = Thread.ofPlatform().start(() -> {
                try (SSLSocket accepted = (SSLSocket) listener.accept()) {
                    accepted.startHandshake();
                    InputStream in = accepted.getInputStream();
                    OutputStream out = accepted.getOutputStream();
                    byte[] buffer = new byte[256];
                    int n;
                    while ((n = in.read(buffer)) > 0) {
                        out.write(buffer, 0, n);
                    }
                } catch (java.io.IOException closed) {
                    // the client went
                }
            });
            TlsConnection connection = ClientHandshake.connectWithoutAuthenticating(
                    SocketTransport.wrap(java.nio.channels.SocketChannel.open(
                            new InetSocketAddress(InetAddress.getLoopbackAddress(),
                                    listener.getLocalPort()))), "localhost");
            try {
                IllegalStateException refused = assertThrows(IllegalStateException.class,
                        () -> SeclumeCrac.quiesceProcess(300));
                assertTrue(refused.getMessage().contains(getClass().getName()),
                        "the refusal does not say who opened the connection: "
                        + refused.getMessage());
                assertFalse(Checkpoint.holding(), "a refused checkpoint holds nothing");
            } finally {
                connection.close();
            }
            server.join(10_000);
            SeclumeCrac.quiesceProcess(2000);
            try {
                assertTrue(Checkpoint.holding() || !SeclumeCrac.HOLD_SECRETS,
                        "closed, and still no checkpoint");
            } finally {
                try {
                    SeclumeCrac.restoredProcess();
                } catch (IllegalStateException noOpenSsl) {
                    // no OpenSSL 3 to reseed; the hold is released regardless
                }
            }
        }
    }
}
