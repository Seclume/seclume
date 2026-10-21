package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Small server keys can be switched off completely: the own TLS stack leaves
 * path validation to the JDK, so {@code jdk.certpath.disabledAlgorithms} - the
 * operator's setting - decides which key sizes a server certificate may have.
 *
 * <p>The property is read once per JVM, so the refusal runs in a child JVM
 * started with a stricter policy; this one checks that the same certificate
 * passes without it, so the child's refusal is the policy's and nothing else.
 */
class KeyLengthPolicyTest {

    private static final String HOST = "db.example.com";

    private static TestCertificates certificates;
    private static Path trustStoreFile;
    private static Path shortLeaf;
    private static Path fullLeaf;

    @BeforeAll
    static void issueAShortAndAFullRsaKey() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        shortLeaf = save(certificates.issueWith("short", List.of("-keyalg", "RSA",
                "-keysize", "1536", "-sigalg", "SHA256withRSA"),
                "san=dns:" + HOST, "ku:c=digitalSignature").certificate(), "short.der");
        fullLeaf = save(certificates.issue("full", "san=dns:" + HOST,
                "ku:c=digitalSignature").certificate(), "full.der");
        trustStoreFile = Files.createTempFile("seclume-trust", ".p12");
        try (OutputStream out = Files.newOutputStream(trustStoreFile)) {
            certificates.trustStore().store(out, TestCertificates.PASSWORD.toCharArray());
        }
    }

    @AfterAll
    static void removeEverythingThatWasGenerated() throws Exception {
        if (certificates != null) {
            certificates.close();
        }
        if (trustStoreFile != null) {
            Files.deleteIfExists(trustStoreFile);
        }
    }

    @Test
    void theJdkDefaultsAcceptTheShortKey() throws Exception {
        CertificateTrust trust = CertificateTrust.of(load(trustStoreFile));
        assertDoesNotThrow(() -> trust.checkServer(List.of(read(shortLeaf)), HOST));
    }

    @Test
    void aPolicyAgainstShortKeysRefusesIt(@TempDir Path temporary) throws Exception {
        Path policy = temporary.resolve("java.security");
        Files.writeString(policy, "jdk.certpath.disabledAlgorithms="
                + Security.getProperty("jdk.certpath.disabledAlgorithms")
                + ", RSA keySize < 2048\n", StandardCharsets.ISO_8859_1);
        Path output = temporary.resolve("child.log");
        String classpath = System.getProperty("surefire.test.class.path",
                System.getProperty("java.class.path"));
        Process child = new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED",
                "-Djava.security.properties=" + policy, "-cp", classpath,
                KeyLengthPolicyTest.class.getName(), trustStoreFile.toString(),
                shortLeaf.toString(), fullLeaf.toString())
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
        try {
            assertTrue(child.waitFor(60, TimeUnit.SECONDS), "the child timed out");
            String report = Files.readString(output);
            assertEquals(0, child.exitValue(), report);
            assertTrue(report.contains("SHORT REFUSED") && report.contains("FULL ACCEPTED"),
                    report);
        } finally {
            child.destroyForcibly();
        }
    }

    /** The child: the 1536-bit leaf refused, the 2048-bit one accepted. */
    public static void main(String[] args) throws Exception {
        CertificateTrust trust = CertificateTrust.of(load(Path.of(args[0])));
        try {
            trust.checkServer(List.of(read(Path.of(args[1]))), HOST);
            System.out.println("SHORT ACCEPTED");
            System.exit(1);
        } catch (CertificateException refused) {
            System.out.println("SHORT REFUSED: " + refused.getMessage());
        }
        trust.checkServer(List.of(read(Path.of(args[2]))), HOST);
        System.out.println("FULL ACCEPTED");
    }

    private static Path save(X509Certificate certificate, String name) throws Exception {
        Path file = Files.createTempFile("seclume-" + name, ".der");
        Files.write(file, certificate.getEncoded());
        return file;
    }

    private static X509Certificate read(Path file) throws Exception {
        try (InputStream in = Files.newInputStream(file)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    private static KeyStore load(Path file) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(file)) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        return store;
    }
}
