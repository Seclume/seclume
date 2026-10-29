package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.crypto.PrivateSigningKey;
import space.seclume.internal.SocketTransport;
import space.seclume.internal.Transport;

/**
 * A connection's client certificate from a stand-in for Vault's PKI - which
 * signs the way Vault does, through keytool, after checking the request's own
 * signature - presented in TLS 1.3 handshakes with seclume's own stack to a
 * server that demands one and trusts only that CA.
 */
@Timeout(120)
class VaultPkiClientIdentityTest {

    private static final String HOSTNAME = "db.example.com";

    private static TestCertificates authority;
    private static SSLContext serverTls;
    private static KeyStore trust;
    private static Path directory;
    private static Path token;

    @BeforeAll
    static void anAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        Assumptions.assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 or CNG here");
        authority = TestCertificates.generate();
        TestCertificates.Issued server = authority.issue("server", "san=dns:" + HOSTNAME
                + ",ip:127.0.0.1", "ku:c=digitalSignature", "eku=serverAuth");
        trust = authority.trustStore();
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(server.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        TrustManagerFactory trusts =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trusts.init(trust);
        serverTls = SSLContext.getInstance("TLSv1.3");
        serverTls.init(keys.getKeyManagers(), trusts.getTrustManagers(), null);
        directory = Files.createTempDirectory("seclume-vault-pki-identity");
        token = Files.writeString(directory.resolve("token"), "hvs.identity-" + System.nanoTime());
    }

    @AfterAll
    static void removeTheAuthority() throws IOException {
        if (authority != null) {
            authority.close();
        }
        if (token != null) {
            Files.deleteIfExists(token);
            Files.deleteIfExists(directory);
        }
    }

    private static Map<String, String> settings(FakeVault vault, String commonName) {
        Map<String, String> settings = new LinkedHashMap<>();
        String p = ClientIdentities.VAULT_PKI_PREFIX;
        settings.put(p + "address", vault.address());
        settings.put(p + "verify", "false");
        settings.put(p + "pki-role", "db-client");
        settings.put(p + "common-name", commonName);
        settings.put(p + "token-provider", "file");
        settings.put(p + "token-path", token.toString());
        return settings;
    }

    @Test
    void aCertificateFromVaultCarriesTheHandshakeAndTheNextOneToo() throws Exception {
        try (FakeVault vault = FakeVault.signing()) {
            ClientIdentity identity = ClientIdentities.of(settings(vault, "orders-a"));
            VaultPkiClientIdentity fromVault =
                    assertInstanceOf(VaultPkiClientIdentity.class, identity);
            try {
                assertEquals(1, vault.requests.size());
                String request = vault.requests.get(0);
                assertTrue(request.startsWith("POST /v1/pki/sign/db-client "), request);
                assertTrue(request.contains("\"common_name\":\"orders-a\""), request);
                assertFalse(request.contains("PRIVATE"), "a private key in the request");
                X509Certificate leaf = certificate(identity.chain().get(0));
                assertEquals("CN=orders-a", leaf.getSubjectX500Principal().getName());
                assertEquals(HandshakeSignature.ECDSA_SECP256R1_SHA256,
                        identity.signatureScheme());
                handshake(identity);

                ClientIdentity inFlight = identity.forHandshake();
                fromVault.renewNow();
                assertEquals(2, fromVault.generations());
                ClientIdentity next = identity.forHandshake();
                assertTrue(next != inFlight, "the renewal was not taken up");
                assertFalse(java.util.Arrays.equals(inFlight.chain().get(0),
                        next.chain().get(0)));
                assertTrue(inFlight.sign("transcript".getBytes(StandardCharsets.US_ASCII))
                        .length > 0, "the version a handshake holds was closed under it");
                handshake(identity);
            } finally {
                identity.close();
            }
            assertThrows(IllegalStateException.class, identity::forHandshake);
        }
    }

    @Test
    void theSameSettingsShareOneIdentityAndOneKey() throws Exception {
        try (FakeVault vault = FakeVault.signing()) {
            ClientIdentity first = ClientIdentities.of(settings(vault, "orders-b"));
            try {
                ClientIdentity second = ClientIdentities.of(settings(vault, "orders-b"));
                assertTrue(first == second, "a pool of fifty would ask Vault fifty times");
                assertEquals(1, vault.requests.size());
            } finally {
                first.close();
            }
        }
    }

    @Test
    void aVaultThatRefusesIsAConnectThatCannotWorkAndIsAskedAgain() throws Exception {
        AtomicBoolean refuse = new AtomicBoolean(true);
        try (FakeVault vault = new FakeVault(body -> refuse.get()
                ? new String[] {"403", "{\"errors\":[\"permission denied\"]}"}
                : FakeVault.sign(body))) {
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> ClientIdentities.of(settings(vault, "orders-c")));
            assertTrue(refused.getMessage().contains("403")
                    && refused.getMessage().contains("/v1/pki/sign/db-client"),
                    refused.getMessage());
            assertFalse(refused.getMessage().contains(Files.readString(token)));
            refuse.set(false);
            ClientIdentity identity = ClientIdentities.of(settings(vault, "orders-c"));
            identity.close();
        }
    }

    @Test
    void oneConnectionPresentsOneCertificate() {
        Map<String, String> both = new LinkedHashMap<>();
        both.put(ClientIdentities.VAULT_PKI_PREFIX + "address", "https://127.0.0.1:1");
        both.put(ClientIdentities.CERTIFICATE, "/etc/tls/client.crt");
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> ClientIdentities.of(both));
        assertTrue(refused.getMessage().contains("one connection presents one"),
                refused.getMessage());
    }

    @Test
    void theRenewalWaitsForTwoThirdsOfTheLife() throws Exception {
        try (FakeVault vault = FakeVault.signing()) {
            VaultPkiClientIdentity identity = (VaultPkiClientIdentity)
                    ClientIdentities.of(settings(vault, "orders-d"));
            try {
                X509Certificate leaf = certificate(identity.chain().get(0));
                assertEquals(space.seclume.secret.VaultPkiIssuer.renewalTime(
                        leaf.getNotBefore().toInstant(), leaf.getNotAfter().toInstant(), 0.67),
                        identity.nextRenewal());
                assertEquals(leaf.getNotAfter().toInstant(), identity.notAfter());
            } finally {
                identity.close();
            }
        }
    }

    private static X509Certificate certificate(byte[] der) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(der));
    }

    private static void handshake(ClientIdentity identity) throws Exception {
        try (EchoServer echo = EchoServer.start(serverTls, true);
                Transport socket = SocketTransport.wrap(java.nio.channels.SocketChannel.open(
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), echo.port())));
                TlsConnection tls = ClientHandshake.connect(socket, HOSTNAME,
                        CertificateTrust.of(trust), identity)) {
            // TLS 1.3 lets the server refuse a client certificate after the
            // client's Finished; data both ways is the proof it was accepted.
            byte[] sent = "select 1".getBytes(StandardCharsets.US_ASCII);
            tls.write(ByteBuffer.wrap(sent));
            ByteBuffer back = ByteBuffer.allocate(sent.length);
            while (back.hasRemaining()) {
                if (tls.read(back) < 0) {
                    throw new IOException("the server closed the connection - it refused the "
                            + "client certificate");
                }
            }
            assertArrayEquals(sent, back.array());
        }
    }

    /** Vault over HTTPS, one request per connection, each request line and body kept. */
    static final class FakeVault implements AutoCloseable {

        final List<String> requests = new CopyOnWriteArrayList<>();
        private final SSLServerSocket socket;
        private volatile boolean stopped;

        static FakeVault signing() throws IOException {
            return new FakeVault(FakeVault::sign);
        }

        /** What pki/sign answers: the certificate for the request's key, and the CA. */
        static String[] sign(String body) {
            Matcher csr = Pattern.compile("\"csr\":\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(body);
            if (!csr.find()) {
                return new String[] {"400", "{\"errors\":[\"no csr\"]}"};
            }
            try {
                String certificate = authority.signRequest(csr.group(1).replace("\\n", "\n"),
                        "ku:c=digitalSignature", "eku=clientAuth");
                return new String[] {"200", "{\"data\":{\"certificate\":\"" + json(certificate)
                        + "\",\"issuing_ca\":\"" + json(authority.caPem()) + "\"}}"};
            } catch (Exception refused) {
                return new String[] {"400", "{\"errors\":[\"" + json(String.valueOf(
                        refused.getMessage())) + "\"]}"};
            }
        }

        private static String json(String text) {
            return text.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
                    .replace("\r", "");
        }

        FakeVault(Function<String, String[]> answer) throws IOException {
            socket = (SSLServerSocket) serverTls.getServerSocketFactory()
                    .createServerSocket(0, 8, InetAddress.getLoopbackAddress());
            Thread thread = new Thread(() -> serve(answer), "fake-vault-pki");
            thread.setDaemon(true);
            thread.start();
        }

        String address() {
            return "https://127.0.0.1:" + socket.getLocalPort();
        }

        private void serve(Function<String, String[]> answer) {
            while (!stopped) {
                try (SSLSocket accepted = (SSLSocket) socket.accept()) {
                    InputStream in = accepted.getInputStream();
                    ByteArrayOutputStream head = new ByteArrayOutputStream();
                    int b;
                    while ((b = in.read()) >= 0) {
                        head.write(b);
                        byte[] seen = head.toByteArray();
                        int n = seen.length;
                        if (n >= 4 && seen[n - 4] == '\r' && seen[n - 3] == '\n'
                                && seen[n - 2] == '\r' && seen[n - 1] == '\n') {
                            break;
                        }
                    }
                    String headers = head.toString(StandardCharsets.US_ASCII);
                    int length = 0;
                    for (String line : headers.split("\r\n")) {
                        if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
                            length = Integer.parseInt(line.substring(15).trim());
                        }
                    }
                    String body = new String(in.readNBytes(length), StandardCharsets.UTF_8);
                    requests.add(headers.substring(0, headers.indexOf("\r\n")) + "\n" + body);
                    String[] reply = answer.apply(body);
                    byte[] out = reply[1].getBytes(StandardCharsets.UTF_8);
                    OutputStream to = accepted.getOutputStream();
                    to.write(("HTTP/1.1 " + reply[0] + " \r\nContent-Type: application/json\r\n"
                            + "Content-Length: " + out.length + "\r\nConnection: close\r\n\r\n")
                            .getBytes(StandardCharsets.US_ASCII));
                    to.write(out);
                    to.flush();
                } catch (IOException | RuntimeException e) {
                    if (stopped) {
                        return;
                    }
                }
            }
        }

        @Override
        public void close() throws IOException {
            stopped = true;
            socket.close();
        }
    }
}
