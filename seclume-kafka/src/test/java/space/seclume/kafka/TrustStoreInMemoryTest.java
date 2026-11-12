package space.seclume.kafka;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.apache.kafka.common.config.types.Password;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.Transport;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;

/**
 * The CA certificates of a JKS or PKCS12 trust store, or of
 * {@code ssl.truststore.certificates}, are what a broker's certificate is
 * checked against - held in memory. Found in the review of 11.11.2026: they
 * were written to a file in the temporary directory, and that file read again
 * at every connection. A cleaner that removed it after its ten days ended
 * every reconnect; and whoever then put a file of that name there - the
 * directory is everybody's - chose whom this client trusts with its password.
 */
@Timeout(120)
class TrustStoreInMemoryTest {

    private static final String PASSWORD = "trust-store-test";

    @TempDir
    static Path directory;
    private static Path brokerTrust;
    private static String brokerPem;
    private static String otherPem;
    private static SSLContext broker;
    private static SSLContext other;

    @BeforeAll
    static void twoBrokersEachWithItsOwnCertificate() throws Exception {
        broker = selfSigned("broker");
        other = selfSigned("other");
        brokerPem = pem("broker");
        otherPem = pem("other");
        brokerTrust = directory.resolve("broker-trust.p12");
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("broker", certificate("broker"));
        try (OutputStream out = Files.newOutputStream(brokerTrust)) {
            trust.store(out, PASSWORD.toCharArray());
        }
    }

    private static SeclumeSslEngineFactory configured(Map<String, Object> options) {
        SeclumeSslEngineFactory factory = new SeclumeSslEngineFactory();
        factory.configure(options);
        return factory;
    }

    private static Map<String, Object> pkcs12() {
        return Map.of("ssl.truststore.type", "PKCS12",
                "ssl.truststore.location", brokerTrust.toString(),
                "ssl.truststore.password", new Password(PASSWORD));
    }

    @Test
    void nothingIsWrittenToTheTemporaryDirectory() throws Exception {
        TreeSet<String> before = trustFilesInTheTemporaryDirectory();
        try (SeclumeSslEngineFactory fromStore = configured(pkcs12());
             SeclumeSslEngineFactory inline = configured(Map.of(
                     "ssl.truststore.certificates", new Password(brokerPem)))) {
            assertEquals(before, trustFilesInTheTemporaryDirectory());
            handshake(fromStore, broker);
            handshake(inline, broker);
            assertThrows(IOException.class, () -> handshake(fromStore, other));
            assertThrows(IOException.class, () -> handshake(inline, other));
        }
    }

    /**
     * What the finding came to: a file of this client's in the temporary
     * directory, rewritten by someone else, decided whom it trusts.
     */
    @Test
    void aFileSomeoneElseWritesDoesNotDecideWhoIsTrusted() throws Exception {
        TreeSet<String> before = trustFilesInTheTemporaryDirectory();
        try (SeclumeSslEngineFactory factory = configured(pkcs12())) {
            TreeSet<String> written = trustFilesInTheTemporaryDirectory();
            written.removeAll(before);
            for (String file : written) {
                Files.writeString(Path.of(System.getProperty("java.io.tmpdir"), file), otherPem);
            }
            assertThrows(IOException.class, () -> handshake(factory, other),
                    "the other broker's certificate was trusted: " + written);
            handshake(factory, broker);
        }
    }

    private static TreeSet<String> trustFilesInTheTemporaryDirectory() throws IOException {
        TreeSet<String> names = new TreeSet<>();
        try (DirectoryStream<Path> files = Files.newDirectoryStream(
                Path.of(System.getProperty("java.io.tmpdir")), "seclume-kafka-trust*")) {
            for (Path file : files) {
                names.add(file.getFileName().toString());
            }
        }
        return names;
    }

    /** A handshake that checks the certificate, with the factory's trust, and one byte each way. */
    private static void handshake(SeclumeSslEngineFactory factory, SSLContext server)
            throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) server.getServerSocketFactory()
                .createServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            listener.setEnabledProtocols(new String[] {"TLSv1.3"});
            Thread serving = Thread.ofVirtual().start(() -> {
                try (SSLSocket client = (SSLSocket) listener.accept()) {
                    client.setSoTimeout(20_000);
                    int b = client.getInputStream().read();
                    if (b >= 0) {
                        client.getOutputStream().write(b);
                        client.getOutputStream().flush();
                    }
                } catch (IOException refusedByTheClient) {
                    // the client did not trust this certificate
                }
            });
            try (Transport socket = SocketTransport.connect("127.0.0.1", listener.getLocalPort(),
                    10_000)) {
                TlsLayer layer;
                try {
                    layer = TrustChoice.using(factory.trust(), () -> {
                        try {
                            return TlsLayers.start(TlsStack.SECLUME, socket, "127.0.0.1",
                                    listener.getLocalPort(), true);
                        } catch (IOException e) {
                            throw new SQLException(e.getMessage(), e);
                        }
                    });
                } catch (SQLException e) {
                    throw new IOException(e.getMessage(), e);
                }
                try {
                    layer.write(ByteBuffer.wrap(new byte[] {42}));
                    ByteBuffer back = ByteBuffer.allocate(1);
                    while (back.hasRemaining()) {
                        if (layer.read(back) < 0) {
                            throw new IOException("closed before the answer");
                        }
                    }
                    assertEquals(42, back.get(0));
                } finally {
                    layer.close();
                }
            } finally {
                serving.join(TimeUnit.SECONDS.toMillis(20));
            }
        }
    }

    private static SSLContext selfSigned(String alias) throws Exception {
        Path store = directory.resolve(alias + ".p12");
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", alias, "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=" + alias, "-ext", "san=ip:127.0.0.1", "-validity", "5",
                "-keystore", store.toString(), "-storetype", "PKCS12",
                "-storepass", PASSWORD, "-keypass", PASSWORD));
        Process keytool = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(keytool.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!keytool.waitFor(60, TimeUnit.SECONDS) || keytool.exitValue() != 0) {
            throw new IllegalStateException("keytool failed: " + output);
        }
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(store)) {
            keys.load(in, PASSWORD.toCharArray());
        }
        KeyManagerFactory factory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keys, PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(factory.getKeyManagers(), null, null);
        return context;
    }

    private static Certificate certificate(String alias) throws Exception {
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(directory.resolve(alias + ".p12"))) {
            keys.load(in, PASSWORD.toCharArray());
        }
        return keys.getCertificate(alias);
    }

    private static String pem(String alias) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'})
                .encodeToString(certificate(alias).getEncoded()) + "\n-----END CERTIFICATE-----\n";
    }
}
