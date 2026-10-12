package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.Transport;

/**
 * A client key in a PKCS#11 token signs a real mutual TLS handshake - against
 * SoftHSM, the software token every distribution packages; a smart card, an
 * HSM or {@code tpm2-pkcs11} answer the same calls.
 *
 * <p>Runs where SoftHSM is installed and {@code SOFTHSM2_CONF} points at a
 * configuration with a writable token directory - the CI's core job sets that
 * up. Skipped everywhere else, including Windows, which has its store.
 */
@Timeout(120)
class Pkcs11ClientIdentityTest {

    private static final String HOSTNAME = "db.example.com";
    private static final String PIN = "4711";

    private static String module;
    private static String token;
    private static TestCertificates authority;
    private static TestCertificates.Issued server;
    private static TestCertificates.Issued client;
    private static Path work;

    @BeforeAll
    static void aTokenWithTheKey() throws Exception {
        Assumptions.assumeTrue(System.getenv("SOFTHSM2_CONF") != null,
                "SOFTHSM2_CONF is not set - no SoftHSM token to test against");
        module = List.of("/usr/lib/softhsm/libsofthsm2.so",
                        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                        "/usr/lib64/pkcs11/libsofthsm2.so", "/usr/lib64/softhsm/libsofthsm.so")
                .stream().filter(path -> Files.exists(Path.of(path))).findFirst().orElse(null);
        Assumptions.assumeTrue(module != null, "no SoftHSM module installed");
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");

        authority = TestCertificates.generate();
        server = authority.issue("server", "san=dns:" + HOSTNAME, "ku:c=digitalSignature",
                "eku=serverAuth");
        client = authority.issueEc("client", "ku:c=digitalSignature", "eku=clientAuth");

        work = Files.createTempDirectory("seclume-pkcs11");
        token = "seclume-" + UUID.randomUUID().toString().substring(0, 8);
        run("softhsm2-util", "--init-token", "--free", "--label", token, "--pin", PIN,
                "--so-pin", "0815");
        // The key goes in as SoftHSM's import wants it: PKCS#8 PEM. A test key,
        // written for the import and deleted after it.
        Path key = work.resolve("key.pem");
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(client.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        PrivateKey privateKey = (PrivateKey) store.getKey("client",
                TestCertificates.PASSWORD.toCharArray());
        Files.writeString(key, "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(privateKey.getEncoded())
                + "\n-----END PRIVATE KEY-----\n");
        run("softhsm2-util", "--import", key.toString(), "--token", token, "--label", "client",
                "--id", "01", "--pin", PIN);
        Files.delete(key);
        // And the certificate beside it, where opensc's tool is there to put it.
        Path der = work.resolve("client.der");
        Files.write(der, client.certificate().getEncoded());
        try {
            run("pkcs11-tool", "--module", module, "--token-label", token, "--login",
                    "--pin", PIN, "--write-object", der.toString(), "--type", "cert",
                    "--label", "client", "--id", "01");
        } catch (IOException noTool) {
            // The chain-from-a-file test still runs.
        }
    }

    @AfterAll
    static void removeTheToken() throws Exception {
        if (token != null) {
            run("softhsm2-util", "--delete-token", "--token", token);
        }
        if (authority != null) {
            authority.close();
        }
    }

    @Test
    void theTokenSignsTheHandshakeWithItsOwnCertificate(@TempDir Path dir) throws Exception {
        Assumptions.assumeTrue(hasTool("pkcs11-tool"), "no pkcs11-tool to put the certificate");
        try (ClientIdentity identity = ClientIdentities.of(settings(dir, null))) {
            assertInstanceOf(Pkcs11ClientIdentity.class, identity);
            assertArrayEquals(client.certificate().getEncoded(), identity.chain().get(0));
            handshake(identity);
        }
    }

    @Test
    void theChainCanComeFromAFile(@TempDir Path dir) throws Exception {
        Path chain = dir.resolve("chain.pem");
        Files.writeString(chain, "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(client.certificate().getEncoded())
                + "\n-----END CERTIFICATE-----\n");
        try (ClientIdentity identity = ClientIdentities.of(settings(dir, chain))) {
            handshake(identity);
        }
    }

    @Test
    void aWrongPinSaysSo(@TempDir Path dir) throws Exception {
        Path wrong = Files.writeString(dir.resolve("wrong-pin"), "0000");
        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> new Pkcs11ClientIdentity(module, token, "client",
                        space.seclume.secret.SecretProviders.of(Map.of("provider", "file",
                                "path", wrong.toString())), null));
        assertTrue(refused.getMessage().contains("CKR_PIN_INCORRECT"), refused.getMessage());
    }

    @Test
    void aKeyThatIsNotThereSaysSo(@TempDir Path dir) throws Exception {
        Path pin = Files.writeString(dir.resolve("pin"), PIN);
        IllegalArgumentException missing = assertThrows(IllegalArgumentException.class,
                () -> new Pkcs11ClientIdentity(module, token, "nobody",
                        space.seclume.secret.SecretProviders.of(Map.of("provider", "file",
                                "path", pin.toString())), null));
        assertTrue(missing.getMessage().contains("'nobody'"), missing.getMessage());
    }

    private static Map<String, String> settings(Path dir, Path chain) throws IOException {
        Path pin = Files.writeString(dir.resolve("pin"), PIN);
        Map<String, String> settings = new HashMap<>();
        settings.put(ClientIdentities.PKCS11, module);
        settings.put(ClientIdentities.PKCS11_TOKEN, token);
        settings.put(ClientIdentities.PKCS11_KEY, "client");
        settings.put(ClientIdentities.PIN_PREFIX + "provider", "file");
        settings.put(ClientIdentities.PIN_PREFIX + "path", pin.toString());
        if (chain != null) {
            settings.put(ClientIdentities.CERTIFICATE, chain.toString());
        }
        return settings;
    }

    private static void handshake(ClientIdentity identity) throws Exception {
        KeyStore clientTrust = KeyStore.getInstance("PKCS12");
        clientTrust.load(null, null);
        clientTrust.setCertificateEntry("client", client.certificate());
        KeyStore serverKeys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(server.keystore())) {
            serverKeys.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(serverKeys, TestCertificates.PASSWORD.toCharArray());
        TrustManagerFactory trusts =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trusts.init(clientTrust);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keys.getKeyManagers(), trusts.getTrustManagers(), null);

        try (EchoServer echo = EchoServer.start(context, true);
             Transport socket = SocketTransport.wrap(java.nio.channels.SocketChannel.open(
                     new InetSocketAddress(InetAddress.getLoopbackAddress(), echo.port())));
             TlsConnection tls = ClientHandshake.connect(socket, HOSTNAME,
                     CertificateTrust.of(authority.trustStore()), identity)) {
            byte[] sent = "select 1".getBytes(StandardCharsets.US_ASCII);
            tls.write(ByteBuffer.wrap(sent));
            ByteBuffer back = ByteBuffer.allocate(sent.length);
            while (back.hasRemaining()) {
                if (tls.read(back) < 0) {
                    throw new IOException("the server refused the client certificate");
                }
            }
            assertArrayEquals(sent, back.array());
        }
    }

    private static boolean hasTool(String tool) {
        try {
            run("sh", "-c", "command -v " + tool);
            return true;
        } catch (IOException | InterruptedException missing) {
            return false;
        }
    }

    private static void run(String... command) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8);
        if (process.waitFor() != 0) {
            throw new IOException(String.join(" ", command[0], command.length > 1 ? command[1]
                    : "") + " failed: " + output.strip());
        }
    }
}
