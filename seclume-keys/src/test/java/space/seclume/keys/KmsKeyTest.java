package space.seclume.keys;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.crypto.CertificationRequest;
import space.seclume.crypto.PrivateSigningKey;
import space.seclume.internal.SocketTransport;
import space.seclume.internal.Transport;
import space.seclume.secret.KmsSigningKey;
import space.seclume.tck.FakeKms;
import space.seclume.tls.CertificateTrust;
import space.seclume.tls.ClientHandshake;
import space.seclume.tls.ClientIdentities;
import space.seclume.tls.ClientIdentity;
import space.seclume.tls.TlsConnection;

/**
 * Keys that live in a key management service - a stand-in for Vault's transit
 * engine ({@link FakeKms}) whose keys {@code openssl} holds and signs with -
 * used as a database connection's client certificate on seclume's own TLS, as
 * a JSSE server's key, and for the certification request that gets each its
 * certificate: the process holds the public half and a token, never the key.
 */
@Timeout(120)
class KmsKeyTest {

    private static Path directory;
    private static Path token;
    private static KeyStore trust;
    private static SSLContext serverTls;

    @BeforeAll
    static void anAuthority() throws Exception {
        Assumptions.assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 here");
        directory = Files.createTempDirectory("seclume-kms");
        token = Files.writeString(directory.resolve("token"), "hvs.kms-" + System.nanoTime());
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-days", "2", "-subj", "/CN=seclume KMS test CA", "-keyout", "ca.key",
                "-out", "ca.pem");
        trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("ca", SeclumeKeys.certificates(directory.resolve("ca.pem"))[0]);
        TrustManagerFactory trusting = TrustManagerFactory.getInstance("PKIX");
        trusting.init(trust);
        // The database side: a server that demands a client certificate from this CA.
        openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-subj", "/CN=localhost", "-keyout", "server.key", "-out", "server.csr");
        Files.writeString(directory.resolve("server.ext"),
                "subjectAltName=DNS:localhost,IP:127.0.0.1\n");
        openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-days", "2", "-extfile", "server.ext", "-out", "server.pem");
        serverTls = SSLContext.getInstance("TLSv1.3");
        serverTls.init(SeclumeKeys.keyManagerFactory(directory.resolve("server.pem"),
                "provider=file&path=" + directory.resolve("server.key")).getKeyManagers(),
                trusting.getTrustManagers(), null);
    }

    @AfterAll
    static void clean() throws IOException {
        ClientIdentities.closeAll();
        if (directory != null) {
            try (var files = Files.walk(directory)) {
                for (Path file : files.sorted(Collections.reverseOrder()).toList()) {
                    Files.deleteIfExists(file);
                }
            }
        }
    }

    private static Map<String, String> settings(FakeKms kms, String keyName) {
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("kms", "vault-transit");
        settings.put("address", kms.address());
        settings.put("verify", "false");
        settings.put("key-name", keyName);
        settings.put("token-provider", "file");
        settings.put("token-path", token.toString());
        return settings;
    }

    private static String spec(Map<String, String> settings) {
        StringBuilder spec = new StringBuilder();
        settings.forEach((name, value) -> spec.append(spec.length() == 0 ? "" : "&")
                .append(name).append('=').append(value));
        return spec.toString();
    }

    /**
     * The certificate for a key in the service: a request signed there, signed
     * by the test CA with {@code openssl x509 -req} - which checks the
     * request's signature, and so the request's algorithm for the key.
     */
    private static Path certify(KmsSigningKey key, String name, String usage) throws Exception {
        Files.writeString(directory.resolve(name + ".csr"),
                CertificationRequest.pem(key, name.equals("server") ? "localhost" : name));
        Files.writeString(directory.resolve(name + ".kms.ext"), "subjectAltName=DNS:localhost,"
                + "IP:127.0.0.1\nextendedKeyUsage=" + usage + "\n");
        openssl("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-days", "2", "-extfile", name + ".kms.ext", "-out",
                name + ".kms.pem");
        return directory.resolve(name + ".kms.pem");
    }

    /** Only the hash travels, and the signature checks out with the public half. */
    @Test
    void theKeySignsInTheServiceAndOnlyAHashIsSent() throws Exception {
        try (FakeKms kms = new FakeKms(FakeKms.KeyType.P256, "orders");
             KmsSigningKey key = KmsSigningKey.of(settings(kms, "orders"))) {
            assertTrue(key.is("EC") && !key.is("RSA"));
            assertTrue(key.name().contains("orders v1"), key.name());
            byte[] message = "a transcript nobody but the peer is to see"
                    .getBytes(StandardCharsets.US_ASCII);
            byte[] signature;
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment in = arena.allocate(message.length);
                MemorySegment.copy(message, 0, in, ValueLayout.JAVA_BYTE, 0, message.length);
                MemorySegment out = arena.allocate(PrivateSigningKey.MAX_SIGNATURE);
                int written = key.sign("SHA256", false, in, message.length, out);
                signature = out.asSlice(0, written).toArray(ValueLayout.JAVA_BYTE);
            }
            Signature verify = Signature.getInstance("SHA256withECDSA");
            verify.initVerify(java.security.KeyFactory.getInstance("EC").generatePublic(
                    new java.security.spec.X509EncodedKeySpec(key.publicKey())));
            verify.update(message);
            assertTrue(verify.verify(signature));

            String encoded = Base64.getEncoder().encodeToString(message);
            assertTrue(kms.requests().stream().noneMatch(r -> r.contains(encoded)
                    || r.contains("transcript")), "the message itself was sent");
            assertTrue(kms.requests().stream().allMatch(r -> !r.startsWith("POST")
                    || r.contains("\"prehashed\":true")), kms.requests().toString());
            assertTrue(kms.requests().get(0).startsWith("GET /v1/transit/keys/orders"),
                    kms.requests().toString());
        }
    }

    /** A database connection's client certificate on seclume's TLS, the key in the service. */
    @Test
    void aDatabaseConnectionPresentsTheKeyInTheService() throws Exception {
        try (FakeKms kms = new FakeKms(FakeKms.KeyType.P384, "db-client")) {
            Path certificate;
            try (KmsSigningKey key = KmsSigningKey.of(settings(kms, "db-client"))) {
                certificate = certify(key, "db-client", "clientAuth");
            }
            Map<String, String> url = new LinkedHashMap<>();
            url.put(ClientIdentities.CERTIFICATE, certificate.toString());
            settings(kms, "db-client").forEach((name, value) ->
                    url.put(ClientIdentities.KEY_PREFIX + name, value));
            ClientIdentity identity = ClientIdentities.of(url);
            try {
                int before = kms.requests().size();
                X509Certificate seen = seclumeHandshake(identity);
                assertTrue(seen.getSubjectX500Principal().getName().contains("CN=db-client"));
                assertTrue(kms.requests().subList(before, kms.requests().size()).stream()
                        .anyMatch(r -> r.startsWith("POST /v1/transit/sign/db-client/sha2-384")),
                        "the handshake was not signed in the service: " + kms.requests());
            } finally {
                identity.close();
            }
        }
    }

    /** A JSSE server whose key is in the service - EC on P-384 and RSA with PSS. */
    @Test
    void aJsseServerSignsItsHandshakeInTheService() throws Exception {
        for (FakeKms.KeyType type : List.of(FakeKms.KeyType.P384, FakeKms.KeyType.RSA2048)) {
            try (FakeKms kms = new FakeKms(type, "web")) {
                Path certificate;
                try (KmsSigningKey key = KmsSigningKey.of(settings(kms, "web"))) {
                    certificate = certify(key, "server", "serverAuth");
                }
                SSLContext server = SSLContext.getInstance("TLSv1.3");
                server.init(SeclumeKeys.keyManagerFactory(certificate,
                        spec(settings(kms, "web"))).getKeyManagers(), null, null);
                TrustManagerFactory trusting = TrustManagerFactory.getInstance("PKIX");
                trusting.init(trust);
                SSLContext client = SSLContext.getInstance("TLSv1.3");
                client.init(null, trusting.getTrustManagers(), null);
                int before = kms.requests().size();
                assertEquals(1, echo(server, client), type.name());
                assertTrue(kms.requests().size() > before, "nothing was signed in the service");
            }
        }
    }

    /** Each signature in the service is a RemoteSignature event: the key, and whether it signed. */
    @Test
    void eachRemoteSignatureIsRecorded() throws Exception {
        try (FakeKms kms = new FakeKms(FakeKms.KeyType.P256, "recorded");
             KmsSigningKey key = KmsSigningKey.of(settings(kms, "recorded"))) {
            var events = space.seclume.tck.Recorded.during(() -> {
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment in = arena.allocate(8);
                    MemorySegment out = arena.allocate(PrivateSigningKey.MAX_SIGNATURE);
                    key.sign("SHA256", false, in, 8, out);
                    kms.refuse(503);
                    assertThrows(IllegalStateException.class,
                            () -> key.sign("SHA256", false, in, 8, out));
                }
            }, "space.seclume.RemoteSignature");
            assertEquals(2, events.size(), events.toString());
            assertTrue(events.get(0).getBoolean("succeeded"));
            assertTrue(events.get(0).getString("key").contains("recorded v1"));
            assertEquals("SHA256", events.get(0).getString("digest"));
            assertFalse(events.get(1).getBoolean("succeeded"));
            assertTrue(events.get(1).getString("reason").contains("503"),
                    events.get(1).getString("reason"));
        }
    }

    /** A key rotated in the service keeps signing as the version its certificate holds. */
    @Test
    void aRotatedKeyStaysWithTheVersionItWasOpenedAt() throws Exception {
        try (FakeKms kms = new FakeKms(FakeKms.KeyType.P256, "rotating");
             KmsSigningKey first = KmsSigningKey.of(settings(kms, "rotating"))) {
            byte[] before = first.publicKey();
            kms.rotate();
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment in = arena.allocate(4);
                MemorySegment out = arena.allocate(PrivateSigningKey.MAX_SIGNATURE);
                first.sign("SHA256", false, in, 4, out);
            }
            assertTrue(kms.requests().get(kms.requests().size() - 1)
                    .contains("\"key_version\":1"), kms.requests().toString());
            Map<String, String> latest = settings(kms, "rotating");
            try (KmsSigningKey second = KmsSigningKey.of(latest)) {
                assertFalse(java.util.Arrays.equals(before, second.publicKey()));
                assertTrue(second.name().contains("rotating v2"), second.name());
            }
            latest.put("key-version", "1");
            try (KmsSigningKey pinned = KmsSigningKey.of(latest)) {
                assertArrayEquals(before, pinned.publicKey());
            }
        }
    }

    @Test
    void whatGoesWrongIsSaid() throws Exception {
        try (FakeKms kms = new FakeKms(FakeKms.KeyType.P256, "orders")) {
            IllegalArgumentException missing = assertThrows(IllegalArgumentException.class,
                    () -> KmsSigningKey.of(settings(kms, "nothing-here")));
            assertTrue(missing.getMessage().contains("404"), missing.getMessage());

            Map<String, String> future = settings(kms, "orders");
            future.put("key-version", "7");
            IllegalArgumentException ahead = assertThrows(IllegalArgumentException.class,
                    () -> KmsSigningKey.of(future));
            assertTrue(ahead.getMessage().contains("past the latest"), ahead.getMessage());

            Map<String, String> plain = settings(kms, "orders");
            plain.put("address", kms.address().replace("https", "http"));
            assertThrows(IllegalArgumentException.class, () -> KmsSigningKey.of(plain));

            Map<String, String> unknown = settings(kms, "orders");
            unknown.put("kms", "carrier-pigeon");
            assertTrue(assertThrows(IllegalArgumentException.class,
                    () -> KmsSigningKey.of(unknown)).getMessage().contains("vault-transit"));

            Map<String, String> both = settings(kms, "orders");
            both.put("provider", "file");
            assertThrows(IllegalArgumentException.class,
                    () -> SeclumeKeys.privateKey(spec(both)));
            assertThrows(IllegalArgumentException.class, () -> SeclumeKeys.keyManager(
                    directory.resolve("ca.pem"), spec(settings(kms, "orders")),
                    java.time.Duration.ofMinutes(1)));

            // A certificate that is not the key's is refused before any connection.
            Map<String, String> url = new LinkedHashMap<>();
            url.put(ClientIdentities.CERTIFICATE, directory.resolve("server.pem").toString());
            settings(kms, "orders").forEach((name, value) ->
                    url.put(ClientIdentities.KEY_PREFIX + name, value));
            IllegalArgumentException foreign = assertThrows(IllegalArgumentException.class,
                    () -> ClientIdentities.of(url));
            assertTrue(foreign.getMessage().contains("is not the key's"), foreign.getMessage());

            // The token may not sign: said when the key is opened, with what it needs.
            kms.refuse(403);
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> KmsSigningKey.of(settings(kms, "orders")));
            assertTrue(refused.getMessage().contains("403")
                    && refused.getMessage().contains("transit/sign/orders"),
                    refused.getMessage());
            assertFalse(refused.getMessage().contains(Files.readString(token)));
        }
    }

    private static X509Certificate seclumeHandshake(ClientIdentity identity) throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) serverTls.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            listener.setNeedClientAuth(true);
            CompletableFuture<X509Certificate> peer = CompletableFuture.supplyAsync(() -> {
                try (SSLSocket accepted = (SSLSocket) listener.accept()) {
                    accepted.startHandshake();
                    X509Certificate seen = (X509Certificate) accepted.getSession()
                            .getPeerCertificates()[0];
                    accepted.getOutputStream().write(accepted.getInputStream().read());
                    accepted.getOutputStream().flush();
                    return seen;
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            });
            try (Transport socket = SocketTransport.wrap(java.nio.channels.SocketChannel.open(
                    new InetSocketAddress(InetAddress.getLoopbackAddress(),
                            listener.getLocalPort())));
                 TlsConnection tls = ClientHandshake.connect(socket, "localhost",
                         CertificateTrust.of(trust), identity)) {
                tls.write(ByteBuffer.wrap(new byte[] {42}));
                ByteBuffer back = ByteBuffer.allocate(1);
                while (back.hasRemaining()) {
                    if (tls.read(back) < 0) {
                        throw new IOException("the server refused the client certificate");
                    }
                }
                assertEquals(42, back.get(0));
            }
            return peer.get(30, TimeUnit.SECONDS);
        }
    }

    /** One byte through a connection between the two contexts. */
    private static int echo(SSLContext server, SSLContext client) throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) server.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            CompletableFuture<Void> served = CompletableFuture.runAsync(() -> {
                try (SSLSocket accepted = (SSLSocket) listener.accept()) {
                    accepted.getOutputStream().write(accepted.getInputStream().read());
                    accepted.getOutputStream().flush();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            });
            try (SSLSocket socket = (SSLSocket) client.getSocketFactory().createSocket(
                    "localhost", listener.getLocalPort())) {
                socket.getOutputStream().write(1);
                int back = socket.getInputStream().read();
                served.get(30, TimeUnit.SECONDS);
                return back;
            }
        }
    }

    private static void openssl(String... arguments) throws IOException, InterruptedException {
        // Through /bin/sh, which finds openssl on the PATH; the arguments stay arguments.
        List<String> command = new ArrayList<>(List.of("-c", "exec openssl \"$@\"", "openssl"));
        command.addAll(List.of(arguments));
        Process process = space.seclume.tck.Shell.builder(command.toArray(String[]::new))
                .directory(directory.toFile()).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8);
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IOException("openssl " + arguments[0] + " failed: " + output);
        }
    }
}
