package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * A certificate authority made for one test run and deleted after it.
 *
 * <p>Generated rather than committed for two reasons. A fixture certificate
 * expires, and then a test fails one day for a reason that has nothing to do
 * with the code - RFC 8448's own certificate expired on 2016-07-30 plus ten
 * years and can no longer pass path validation, which is why
 * {@code CertificateVerificationTest} only verifies its signature. And a
 * committed private key would be the wrong file in this repository of all
 * repositories.
 */
final class TestCertificates implements AutoCloseable {

    static final String PASSWORD = "seclume-test";

    /** A certificate and the keystore holding its private key and chain. */
    record Issued(X509Certificate certificate, Path keystore) {
    }

    private final Path directory;
    private final String keytool;
    private final Path caStore;
    private final X509Certificate ca;
    private final KeyStore trustStore;

    private TestCertificates(Path directory, String keytool, Path caStore, X509Certificate ca,
            KeyStore trustStore) {
        this.directory = directory;
        this.keytool = keytool;
        this.caStore = caStore;
        this.ca = ca;
        this.trustStore = trustStore;
    }

    /** Whether this JDK ships the tool everything here is built with. */
    static boolean available() {
        return Files.isExecutable(keytoolPath());
    }

    private static Path keytoolPath() {
        boolean windows = System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");
        return Path.of(System.getProperty("java.home"), "bin", windows ? "keytool.exe" : "keytool");
    }

    static TestCertificates generate() throws Exception {
        Path directory = Files.createTempDirectory("seclume-certs");
        String keytool = keytoolPath().toString();
        Path caStore = directory.resolve("ca.p12");
        run(List.of(keytool, "-genkeypair", "-alias", "ca", "-keyalg", "RSA", "-keysize", "2048",
                "-sigalg", "SHA256withRSA", "-dname", "CN=seclume-test-ca", "-validity", "2",
                "-ext", "bc:c", "-keystore", caStore.toString(), "-storetype", "PKCS12",
                "-storepass", PASSWORD, "-keypass", PASSWORD));

        Path caFile = directory.resolve("ca.cer");
        run(List.of(keytool, "-exportcert", "-alias", "ca", "-keystore", caStore.toString(),
                "-storepass", PASSWORD, "-rfc", "-file", caFile.toString()));
        X509Certificate ca = read(caFile);

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("seclume-test-ca", ca);
        return new TestCertificates(directory, keytool, caStore, ca, trustStore);
    }

    X509Certificate authority() {
        return ca;
    }

    /** The anchors a client should be given to accept what {@link #issue} produces. */
    KeyStore trustStore() {
        return trustStore;
    }

    /**
     * A key pair signed by this authority.
     *
     * <p>The returned keystore holds the signed certificate and its issuer, so
     * it can be handed to a {@code KeyManagerFactory} and serve as a TLS
     * server identity - which needs the chain, not just the key.
     */
    Issued issue(String alias, String... extensions) throws Exception {
        Path store = directory.resolve(alias + ".p12");
        Path request = directory.resolve(alias + ".csr");
        Path signed = directory.resolve(alias + ".cer");

        run(List.of(keytool, "-genkeypair", "-alias", alias, "-keyalg", "RSA", "-keysize", "2048",
                "-sigalg", "SHA256withRSA", "-dname", "CN=" + alias, "-validity", "2",
                "-keystore", store.toString(), "-storetype", "PKCS12",
                "-storepass", PASSWORD, "-keypass", PASSWORD));
        run(List.of(keytool, "-certreq", "-alias", alias, "-keystore", store.toString(),
                "-storepass", PASSWORD, "-file", request.toString()));

        List<String> gencert = new ArrayList<>(List.of(keytool, "-gencert", "-alias", "ca",
                "-keystore", caStore.toString(), "-storepass", PASSWORD,
                "-sigalg", "SHA256withRSA", "-validity", "2",
                "-infile", request.toString(), "-outfile", signed.toString(), "-rfc"));
        for (String extension : extensions) {
            gencert.add("-ext");
            gencert.add(extension);
        }
        run(gencert);

        run(List.of(keytool, "-importcert", "-noprompt", "-alias", "ca",
                "-file", directory.resolve("ca.cer").toString(),
                "-keystore", store.toString(), "-storepass", PASSWORD));
        run(List.of(keytool, "-importcert", "-noprompt", "-alias", alias,
                "-file", signed.toString(),
                "-keystore", store.toString(), "-storepass", PASSWORD));
        return new Issued(read(signed), store);
    }

    private static X509Certificate read(Path file) throws Exception {
        try (InputStream in = Files.newInputStream(file)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    private static void run(List<String> command) throws Exception {
        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .start();
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "keytool did not finish: " + command);
        assertTrue(process.exitValue() == 0,
                "keytool failed with " + process.exitValue() + ": " + String.join(" ", command));
    }

    @Override
    public void close() throws IOException {
        try (var walk = Files.walk(directory)) {
            for (Path path : walk.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
        assertTrue(Files.notExists(directory), "the generated keys and certificates are gone");
    }
}
