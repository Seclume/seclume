package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Certificate trust against a CA made for this test run.
 *
 * <p>The certificates are generated rather than committed, and the reason is
 * the trap they would otherwise become: a fixture certificate expires, and
 * the test that depended on it fails one day for a reason that has nothing to
 * do with the code. (RFC 8448's own certificate expired on 2016-07-30 +
 * ten years - it can be parsed and its signature verified, which is what
 * {@code CertificateVerificationTest} does with it, but it can no longer pass
 * path validation.) Generating them also keeps a private key out of the
 * repository, which in this project of all projects would be the wrong file
 * to commit.
 *
 * <p>The positive case matters as much as the refusals: a validator that
 * rejected everything would pass every "must be refused" test there is.
 */
class CertificateTrustTest {

    private static final String PASSWORD = "seclume-test";

    private static Path directory;
    private static X509Certificate caCertificate;
    private static X509Certificate leaf;               // digitalSignature, three SANs
    private static X509Certificate encipherOnlyLeaf;   // keyEncipherment only
    private static KeyStore trustStore;
    private static SSLContext serverContext;           // presents the leaf, for the JSSE oracle
    private static SSLContext clientContext;           // trusts the test CA, for the JSSE oracle

    @BeforeAll
    static void generateAPrivateCertificateAuthority() throws Exception {
        Path keytool = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").toLowerCase(java.util.Locale.ROOT).contains("win")
                        ? "keytool.exe" : "keytool");
        Assumptions.assumeTrue(Files.isExecutable(keytool), "no keytool in this JDK");

        directory = Files.createTempDirectory("seclume-trust");
        String tool = keytool.toString();
        Path caStore = directory.resolve("ca.p12");
        Path leafStore = directory.resolve("leaf.p12");
        Path encipherStore = directory.resolve("encipher.p12");

        keypair(tool, caStore, "ca", "CN=seclume-test-ca", "bc:c");
        keypair(tool, leafStore, "leaf", "CN=seclume-leaf", null);
        keypair(tool, encipherStore, "leaf", "CN=seclume-encipher-leaf", null);

        caCertificate = export(tool, caStore, "ca");
        Path signedLeaf = sign(tool, caStore, leafStore, "leaf",
                "san=dns:db.example.com,dns:*.wild.example.com,ip:10.1.2.3",
                "ku:c=digitalSignature");
        leaf = read(signedLeaf);
        encipherOnlyLeaf = read(sign(tool, caStore, encipherStore, "leaf",
                "san=dns:db.example.com", "ku:c=keyEncipherment"));

        trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("seclume-test-ca", caCertificate);

        // For the live-handshake oracle below the leaf keystore has to hold the
        // signed certificate and its issuer, not the self-signed one it was born with.
        Path caFile = caStore.resolveSibling("ca.cer");
        run(List.of(tool, "-importcert", "-noprompt", "-alias", "ca", "-file", caFile.toString(),
                "-keystore", leafStore.toString(), "-storepass", PASSWORD));
        run(List.of(tool, "-importcert", "-noprompt", "-alias", "leaf",
                "-file", signedLeaf.toString(),
                "-keystore", leafStore.toString(), "-storepass", PASSWORD));
        serverContext = serverContext(leafStore);
        clientContext = clientContext(trustStore);
    }

    @AfterAll
    static void removeEverythingThatWasGenerated() throws IOException {
        if (directory == null) {
            return;
        }
        try (var walk = Files.walk(directory)) {
            for (Path path : walk.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
        assertTrue(Files.notExists(directory), "the generated keys and certificates are gone");
    }

    // ---- the chain --------------------------------------------------------

    /**
     * The positive control - and it says more than "a good chain passes".
     * This leaf carries <b>only</b> {@code digitalSignature}, so it also pins
     * down {@code CertificateTrust}'s TLS 1.3 authentication type: were it
     * {@code "RSA"}, the JDK would demand {@code keyEncipherment} and refuse
     * a perfectly ordinary TLS 1.3 certificate.
     */
    @Test
    void aChainToATrustedAuthorityIsAcceptedForItsOwnName() throws Exception {
        CertificateTrust trust = CertificateTrust.of(trustStore);
        assertDoesNotThrow(() -> trust.checkServer(List.of(leaf), "db.example.com"));
    }

    @Test
    void theSameChainIsRefusedByTheJvmsOwnTrustStore() throws Exception {
        CertificateTrust trust = CertificateTrust.ofDefaultTrustStore();
        CertificateException refused = assertThrows(CertificateException.class,
                () -> trust.checkServer(List.of(leaf), "db.example.com"));
        assertTrue(refused.getMessage() == null || !refused.getMessage().contains("db.example.com"),
                "this must fail on the chain, not on the name - otherwise the test proves nothing "
                        + "about cacerts: " + refused.getMessage());
    }

    /**
     * The other side of the authentication-type coin: this leaf chains to the
     * same trusted CA and carries the right name, and differs only in
     * carrying {@code keyEncipherment} instead of {@code digitalSignature}.
     * TLS 1.3 authenticates a server by signature, so this certificate cannot
     * do the job - and the refusal proves the key-usage check is live rather
     * than something the previous test passed by being ignored.
     */
    @Test
    void aCertificateThatCannotSignIsRefusedForTls13() throws Exception {
        CertificateTrust trust = CertificateTrust.of(trustStore);
        assertThrows(CertificateException.class,
                () -> trust.checkServer(List.of(encipherOnlyLeaf), "db.example.com"));
    }

    @Test
    void anEmptyChainIsRefused() throws Exception {
        CertificateTrust trust = CertificateTrust.of(trustStore);
        assertThrows(CertificateException.class, () -> trust.checkServer(List.of(), "db.example.com"));
    }

    // ---- the name ---------------------------------------------------------

    @Test
    void aGoodChainForTheWrongNameIsRefused() throws Exception {
        CertificateTrust trust = CertificateTrust.of(trustStore);
        CertificateException refused = assertThrows(CertificateException.class,
                () -> trust.checkServer(List.of(leaf), "other.example.com"));
        assertTrue(refused.getMessage().contains("other.example.com"),
                "the message has to name the host that was asked for: " + refused.getMessage());
    }

    @Test
    void aWildcardCoversOneLabelAndNoMore() throws Exception {
        CertificateTrust trust = CertificateTrust.of(trustStore);
        assertDoesNotThrow(() -> trust.checkServer(List.of(leaf), "db.wild.example.com"));
        assertThrows(CertificateException.class,
                () -> trust.checkServer(List.of(leaf), "a.b.wild.example.com"));
        assertThrows(CertificateException.class,
                () -> trust.checkServer(List.of(leaf), "wild.example.com"));
    }

    @Test
    void anAddressMatchesOnlyTheAddressInTheCertificate() throws Exception {
        CertificateTrust trust = CertificateTrust.of(trustStore);
        assertDoesNotThrow(() -> trust.checkServer(List.of(leaf), "10.1.2.3"));
        assertThrows(CertificateException.class, () -> trust.checkServer(List.of(leaf), "10.1.2.4"));
    }

    /**
     * The differential test that makes "we wrote our own hostname check"
     * something checked rather than claimed.
     *
     * <p>The oracle is a <b>real TLS handshake</b> over the loopback
     * interface, between JSSE and JSSE, with the client's
     * {@code endpointIdentificationAlgorithm} set to {@code HTTPS} and the
     * peer name supplied through
     * {@link javax.net.ssl.SSLSocketFactory#createSocket(java.net.Socket, String, int, boolean)}.
     * That is the only way to reach the JDK's own {@code HostnameChecker}
     * through public API: it lives behind {@code X509ExtendedTrustManager},
     * which performs the check only when it can read a handshake session -
     * which is exactly why {@link HostnameMatch} has to exist at all.
     * ({@link HttpsURLConnection#getDefaultHostnameVerifier()} looks like the
     * shortcut and is not one: it is a fallback that refuses everything, and
     * an earlier version of this test skipped itself because of it.)
     *
     * <p>The property asserted is one-sided on purpose: <b>wherever we say
     * yes, JSSE must say yes too.</b> Being stricter than the JDK is a
     * decision this project made (no partial-label wildcards, no wildcard
     * above three labels); being more permissive would be a defect, and this
     * is what would catch one.
     */
    @Test
    void weAreNeverMorePermissiveThanJsseDoingTheSameCheck() throws Exception {
        Assumptions.assumeTrue(jsseAccepts("db.example.com"),
                "JSSE did not accept even the exact name over loopback - the oracle is not "
                        + "working, and comparing against a broken one would prove nothing");

        List<String> hosts = List.of(
                "db.example.com", "DB.example.com", "db.example.com.",
                "other.example.com", "db.example.com.evil.test",
                "x.wild.example.com", "a.b.wild.example.com", "wild.example.com",
                "10.1.2.3", "10.1.2.4", "example.com", "com",
                ".example.com", "*.example.com");

        int accepted = 0;
        for (String host : hosts) {
            if (HostnameMatch.matches(leaf, host)) {
                assertTrue(jsseAccepts(host), "we accept \"" + host + "\" and JSSE does not - "
                        + "being more permissive than the JDK's own check is never intended");
                accepted++;
            }
        }
        assertTrue(accepted >= 3, "the comparison accepted almost nothing, so it checked almost "
                + "nothing - accepted " + accepted);
    }

    // ---- fixtures ---------------------------------------------------------

    /**
     * One loopback handshake, asking JSSE the question this test cannot ask
     * it directly: is this certificate good for this name? A refusal arrives
     * as a failed handshake, which is the answer rather than an error.
     */
    private static boolean jsseAccepts(String host) throws Exception {
        try (SSLServerSocket server = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            server.setSoTimeout(30_000);
            Thread accepting = Thread.ofVirtual().start(() -> {
                try (SSLSocket accepted = (SSLSocket) server.accept()) {
                    accepted.startHandshake();
                    accepted.getInputStream().read();
                } catch (Exception ignored) {
                    // a client that refuses the certificate lands here; that is the answer
                }
            });
            try (Socket plain = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort())) {
                SSLSocket client = (SSLSocket) clientContext.getSocketFactory()
                        .createSocket(plain, host, server.getLocalPort(), true);
                SSLParameters parameters = client.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                client.setSSLParameters(parameters);
                client.setSoTimeout(30_000);
                client.startHandshake();
                client.close();
                return true;
            } catch (Exception refused) {
                return false;
            } finally {
                accepting.join(java.time.Duration.ofSeconds(30));
            }
        }
    }

    private static SSLContext serverContext(Path keystore) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            store.load(in, PASSWORD.toCharArray());
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keys.getKeyManagers(), null, null);
        return context;
    }

    private static SSLContext clientContext(KeyStore anchors) throws Exception {
        TrustManagerFactory trust =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(anchors);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(null, trust.getTrustManagers(), null);
        return context;
    }

    private static void keypair(String keytool, Path store, String alias, String dname,
            String extension) throws Exception {
        var command = new java.util.ArrayList<>(List.of(keytool,
                "-genkeypair", "-alias", alias, "-keyalg", "RSA", "-keysize", "2048",
                "-sigalg", "SHA256withRSA", "-dname", dname, "-validity", "2",
                "-keystore", store.toString(), "-storetype", "PKCS12",
                "-storepass", PASSWORD, "-keypass", PASSWORD));
        if (extension != null) {
            command.add("-ext");
            command.add(extension);
        }
        run(command);
    }

    private static Path sign(String keytool, Path caStore, Path leafStore, String alias,
            String... extensions) throws Exception {
        Path request = leafStore.resolveSibling(alias + "-" + leafStore.getFileName() + ".csr");
        Path signed = leafStore.resolveSibling(alias + "-" + leafStore.getFileName() + ".cer");
        run(List.of(keytool, "-certreq", "-alias", alias, "-keystore", leafStore.toString(),
                "-storepass", PASSWORD, "-file", request.toString()));

        var command = new java.util.ArrayList<>(List.of(keytool,
                "-gencert", "-alias", "ca", "-keystore", caStore.toString(),
                "-storepass", PASSWORD, "-sigalg", "SHA256withRSA", "-validity", "2",
                "-infile", request.toString(), "-outfile", signed.toString(), "-rfc"));
        for (String extension : extensions) {
            command.add("-ext");
            command.add(extension);
        }
        run(command);
        return signed;
    }

    private static X509Certificate export(String keytool, Path store, String alias) throws Exception {
        Path file = store.resolveSibling(alias + ".cer");
        run(List.of(keytool, "-exportcert", "-alias", alias, "-keystore", store.toString(),
                "-storepass", PASSWORD, "-rfc", "-file", file.toString()));
        return read(file);
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
}
