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
public final class TestCertificates implements AutoCloseable {

    public static final String PASSWORD = "seclume-test";

    /** A certificate and the keystore holding its private key and chain. */
    public record Issued(X509Certificate certificate, Path keystore) {
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
    public static boolean available() {
        return Files.isExecutable(keytoolPath());
    }

    private static Path keytoolPath() {
        boolean windows = System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");
        return Path.of(System.getProperty("java.home"), "bin", windows ? "keytool.exe" : "keytool");
    }

    public static TestCertificates generate() throws Exception {
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
    public KeyStore trustStore() {
        return trustStore;
    }

    /**
     * A key pair signed by this authority.
     *
     * <p>The returned keystore holds the signed certificate and its issuer, so
     * it can be handed to a {@code KeyManagerFactory} and serve as a TLS
     * server identity - which needs the chain, not just the key.
     */
    public Issued issue(String alias, String... extensions) throws Exception {
        return issue(alias, false, extensions);
    }

    /**
     * The same with a P-256 key instead of RSA.
     *
     * <p>Needed for the client identity: seclume signs a client
     * CertificateVerify with P-256 and nothing else, because that is the curve
     * it can sign with off the heap.
     */
    public Issued issueEc(String alias, String... extensions) throws Exception {
        return issue(alias, "secp256r1", extensions);
    }

    /** The same on P-384 - what FIPS and CNSA configurations issue. */
    public Issued issueP384(String alias, String... extensions) throws Exception {
        return issue(alias, "secp384r1", extensions);
    }

    private Issued issue(String alias, boolean ec, String... extensions) throws Exception {
        return issue(alias, ec ? "secp256r1" : null, extensions);
    }

    /** @param group the EC group, or null for RSA */
    private Issued issue(String alias, String group, String... extensions) throws Exception {
        List<String> key = group != null
                ? List.of("-keyalg", "EC", "-groupname", group, "-sigalg",
                        group.equals("secp384r1") ? "SHA384withECDSA" : "SHA256withECDSA")
                : List.of("-keyalg", "RSA", "-keysize", "2048", "-sigalg", "SHA256withRSA");
        return issueWith(alias, key, extensions);
    }

    /**
     * Any key keytool makes: {@code -keyalg Ed25519}, or {@code -keyalg
     * RSASSA-PSS} for an RSA key restricted to PSS - the certificates whose
     * signature schemes a client has to offer by name.
     */
    public Issued issueWith(String alias, List<String> keyOptions, String... extensions)
            throws Exception {
        Path store = directory.resolve(alias + ".p12");
        Path request = directory.resolve(alias + ".csr");
        Path signed = directory.resolve(alias + ".cer");

        List<String> command = new ArrayList<>(List.of(keytool, "-genkeypair", "-alias", alias));
        command.addAll(keyOptions);
        command.addAll(List.of("-dname", "CN=" + alias, "-validity", "2",
                "-keystore", store.toString(), "-storetype", "PKCS12",
                "-storepass", PASSWORD, "-keypass", PASSWORD));
        run(command);
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

    /** Where keytool's own output goes: nowhere, and never closed. */
    private static final java.io.PrintStream SILENT =
            new java.io.PrintStream(java.io.OutputStream.nullOutputStream());

    /**
     * The JDK's own keytool, called in this JVM when the build exports it
     * ({@code --add-exports java.base/sun.security.tools.keytool=ALL-UNNAMED}):
     * the same tool and the same files, without a JVM start per step - some
     * two hundred of them in this module. Otherwise, a process as before.
     */
    private static final java.lang.reflect.Method IN_PROCESS = inProcess();

    private static java.lang.reflect.Method inProcess() {
        try {
            Class<?> main = Class.forName("sun.security.tools.keytool.Main");
            java.lang.reflect.Method run = main.getMethod("run", String[].class,
                    java.io.PrintStream.class);
            run.invoke(main.getConstructor().newInstance(), new String[] {"-help"},
                    SILENT);
            return run;
        } catch (ReflectiveOperationException | RuntimeException notExported) {
            return null;
        }
    }

    private static void run(List<String> command) throws Exception {
        if (IN_PROCESS != null) {
            String[] arguments = command.subList(1, command.size()).toArray(String[]::new);
            int exit;
            // One at a time: keytool was written as a program, not as a
            // library, and nothing promises its statics are safe to share.
            synchronized (IN_PROCESS) {
                try {
                    exit = (int) IN_PROCESS.invoke(IN_PROCESS.getDeclaringClass()
                            .getConstructor().newInstance(), arguments,
                            SILENT);
                } catch (java.lang.reflect.InvocationTargetException failed) {
                    throw new AssertionError("keytool failed: " + String.join(" ", command),
                            failed.getCause());
                }
            }
            assertTrue(exit == 0, "keytool failed with " + exit + ": " + String.join(" ", command));
            return;
        }
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
