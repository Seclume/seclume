package space.seclume.http;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import space.seclume.internal.TrustChoice;

/**
 * A self-signed server certificate for {@code localhost}, made with the JDK's
 * keytool, and what a test needs of it: an SSLContext for the fake server and
 * the pin for {@code tlsPin=}.
 */
final class TestPki {

    static final String STORE_PASSWORD = "seclume-test";

    final Path keystore;
    final X509Certificate certificate;

    private TestPki(Path keystore, X509Certificate certificate) {
        this.keystore = keystore;
        this.certificate = certificate;
    }

    static TestPki generate() throws Exception {
        Path directory = Files.createTempDirectory("seclume-http-pki");
        Path keystore = directory.resolve("server.p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").startsWith("Windows") ? "keytool.exe" : "keytool")
                .toString();
        Process process = new ProcessBuilder(List.of(keytool, "-genkeypair", "-alias", "server",
                "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
                "-dname", "CN=localhost", "-ext", "san=dns:localhost,ip:127.0.0.1",
                "-storetype", "PKCS12", "-keystore", keystore.toString(),
                "-storepass", STORE_PASSWORD, "-keypass", STORE_PASSWORD))
                .redirectErrorStream(true).start();
        process.getInputStream().readAllBytes();
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException("keytool failed");
        }
        return load(keystore);
    }

    static TestPki load(Path keystore) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            store.load(in, STORE_PASSWORD.toCharArray());
        }
        return new TestPki(keystore, (X509Certificate) store.getCertificate("server"));
    }

    String pin() {
        return TrustChoice.pinOf(certificate);
    }

    SSLContext serverContext() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            store.load(in, STORE_PASSWORD.toCharArray());
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, STORE_PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keys.getKeyManagers(), null, null);
        return context;
    }
}
