package space.seclume.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
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
import space.seclume.secret.SpiffeWorkloadApi;
import space.seclume.tck.FakeWorkloadApi;
import space.seclume.tls.CertificateTrust;
import space.seclume.tls.ClientHandshake;
import space.seclume.tls.ClientIdentities;
import space.seclume.tls.ClientIdentity;
import space.seclume.tls.TlsConnection;

/**
 * X.509-SVIDs from a stand-in for a SPIRE agent ({@link FakeWorkloadApi}),
 * made by the {@code openssl} command line for a trust domain of its own: the
 * Workload API's answer read with the key in native memory, a database
 * connection's client certificate with seclume's TLS, mutual TLS between two
 * workloads with JSSE, and a rotated SVID taken up.
 */
@Timeout(120)
class SpiffeTest {

    private static final String ORDERS = "spiffe://example.org/orders";
    private static final String PAYMENTS = "spiffe://example.org/payments";

    private static Path directory;
    private static SSLContext serverTls;
    private static KeyStore trust;
    private static byte[] ca;
    private static Svid first;
    private static Svid second;
    private static Svid payments;

    /** One SVID's parts as the agent sends them: the certificate and its PKCS#8 key, DER. */
    record Svid(byte[] certificate, byte[] key) {
        byte[] answer(String id) {
            return FakeWorkloadApi.x509SvidResponse(id, certificate, key, ca);
        }
    }

    @BeforeAll
    static void aTrustDomain() throws Exception {
        Assumptions.assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 here");
        directory = Files.createTempDirectory("seclume-spiffe");
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-days", "2", "-subj", "/O=example.org", "-keyout", "ca.key", "-out", "ca.pem");
        openssl("x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der");
        ca = Files.readAllBytes(directory.resolve("ca.der"));
        first = svid("first", ORDERS);
        second = svid("second", ORDERS);
        payments = svid("payments", PAYMENTS);
        // A server for the database side: localhost, from the same CA.
        openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-subj", "/CN=localhost", "-keyout", "server.key", "-out", "server.csr");
        Files.writeString(directory.resolve("server.ext"),
                "subjectAltName=DNS:localhost,IP:127.0.0.1\n");
        openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-days", "2", "-extfile", "server.ext", "-out", "server.pem");
        trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("ca", SeclumeKeys.certificates(directory.resolve("ca.pem"))[0]);
        TrustManagerFactory trusting = TrustManagerFactory.getInstance("PKIX");
        trusting.init(trust);
        serverTls = SSLContext.getInstance("TLSv1.3");
        serverTls.init(SeclumeKeys.keyManagerFactory(directory.resolve("server.pem"),
                "provider=file&path=" + directory.resolve("server.key")).getKeyManagers(),
                trusting.getTrustManagers(), null);
    }

    private static Svid svid(String name, String id) throws Exception {
        openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-subj", "/O=example.org", "-keyout", name + ".key", "-out", name + ".csr");
        Files.writeString(directory.resolve(name + ".ext"), "subjectAltName=URI:" + id
                + "\nextendedKeyUsage=clientAuth,serverAuth\nkeyUsage=digitalSignature\n");
        openssl("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-days", "2", "-extfile", name + ".ext", "-outform", "DER",
                "-out", name + ".der");
        openssl("pkcs8", "-topk8", "-nocrypt", "-in", name + ".key", "-outform", "DER",
                "-out", name + ".p8");
        return new Svid(Files.readAllBytes(directory.resolve(name + ".der")),
                Files.readAllBytes(directory.resolve(name + ".p8")));
    }

    @AfterAll
    static void clean() throws IOException {
        if (directory != null) {
            try (var files = Files.walk(directory)) {
                for (Path file : files.sorted(Collections.reverseOrder()).toList()) {
                    Files.deleteIfExists(file);
                }
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

    private static Path socket(String name) {
        return directory.resolve(name + ".sock");
    }

    @Test
    void theAnswerIsReadWithItsKeyInNativeMemory() throws Exception {
        try (FakeWorkloadApi agent = new FakeWorkloadApi(socket("read"),
                () -> first.answer(ORDERS))) {
            for (FakeWorkloadApi.Mode mode : List.of(FakeWorkloadApi.Mode.ANSWER,
                    FakeWorkloadApi.Mode.SPLIT)) {
                agent.mode(mode);
                SpiffeWorkloadApi.X509Svid svid = new SpiffeWorkloadApi(agent.socket(), 10_000)
                        .fetchX509Svid();
                try (PrivateSigningKey key = svid.key()) {
                    assertEquals(ORDERS, svid.spiffeId(), mode.toString());
                    assertEquals(1, svid.chain().size());
                    assertEquals(1, svid.bundle().size());
                    byte[] message = "a transcript".getBytes(StandardCharsets.US_ASCII);
                    byte[] signature;
                    try (Arena arena = Arena.ofConfined()) {
                        MemorySegment in = arena.allocate(message.length);
                        MemorySegment.copy(message, 0, in, ValueLayout.JAVA_BYTE, 0,
                                message.length);
                        MemorySegment out = arena.allocate(PrivateSigningKey.MAX_SIGNATURE);
                        int n = key.sign("SHA256", false, in, message.length, out);
                        signature = out.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE);
                    }
                    Signature check = Signature.getInstance("SHA256withECDSA");
                    check.initVerify(svid.chain().get(0).getPublicKey());
                    check.update(message);
                    assertTrue(check.verify(signature), "the key is not the certificate's");
                }
            }
            String request = agent.headerBlocks().get(0);
            assertTrue(request.contains(":path: /SpiffeWorkloadAPI/FetchX509SVID\n")
                    && request.contains("workload.spiffe.io: true\n")
                    && request.contains("content-type: application/grpc\n"), request);
        }
    }

    @Test
    void whatGoesWrongIsSaid() throws Exception {
        try (FakeWorkloadApi agent = new FakeWorkloadApi(socket("wrong"),
                () -> FakeWorkloadApi.x509SvidResponse(ORDERS, first.certificate(),
                        second.key(), ca))) {
            IOException foreign = assertThrows(IOException.class,
                    () -> new SpiffeWorkloadApi(agent.socket(), 10_000).fetchX509Svid());
            assertTrue(foreign.getMessage().contains("not its certificate's"),
                    foreign.getMessage());
            agent.mode(FakeWorkloadApi.Mode.UNREGISTERED);
            IOException unregistered = assertThrows(IOException.class,
                    () -> new SpiffeWorkloadApi(agent.socket(), 10_000).fetchX509Svid());
            assertTrue(unregistered.getMessage().contains("registered"),
                    unregistered.getMessage());
            agent.mode(FakeWorkloadApi.Mode.SILENT);
            IOException silent = assertThrows(IOException.class,
                    () -> new SpiffeWorkloadApi(agent.socket(), 500).fetchX509Svid());
            assertTrue(silent.getMessage().contains("did not answer within 500 ms"),
                    silent.getMessage());
        }
        IOException none = assertThrows(IOException.class,
                () -> new SpiffeWorkloadApi(socket("absent"), 1000).fetchX509Svid());
        assertTrue(none.getMessage().contains("could not be reached"), none.getMessage());
        assertEquals(Path.of("/run/spire/agent.sock"),
                SpiffeWorkloadApi.socketOf("unix:///run/spire/agent.sock"));
        assertEquals(Path.of("/run/spire/agent.sock"),
                SpiffeWorkloadApi.socketOf("unix:/run/spire/agent.sock"));
        assertThrows(IllegalArgumentException.class,
                () -> SpiffeWorkloadApi.socketOf("tcp://127.0.0.1:8081"));
        assertEquals(10_000, SpiffeWorkloadApi.timeoutMillis("timeout-millis", null, 10_000));
        assertEquals(250, SpiffeWorkloadApi.timeoutMillis("timeout-millis", " 250 ", 10_000));
        for (String wrong : new String[] {"soon", "0", "-5"}) {
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> SeclumeKeys.spiffeKeyManager("socket=unix:///nowhere&timeout-millis="
                            + wrong));
            assertTrue(refused.getMessage().contains("timeout-millis is how many milliseconds")
                    && refused.getMessage().endsWith("not " + wrong), refused.getMessage());
        }
    }

    /** The SVID as a database connection's client certificate, with seclume's own TLS. */
    @Test
    void theSvidLogsADatabaseConnectionIn() throws Exception {
        try (FakeWorkloadApi agent = new FakeWorkloadApi(socket("jdbc"),
                () -> first.answer(ORDERS))) {
            ClientIdentity identity = ClientIdentities.of(Map.of(ClientIdentities.SPIFFE,
                    "unix://" + agent.socket()));
            try {
                X509Certificate peer = seclumeHandshake(identity);
                assertTrue(peer.getSubjectAlternativeNames().toString().contains(ORDERS),
                        peer.getSubjectAlternativeNames().toString());
            } finally {
                identity.close();
            }
            assertThrows(IllegalArgumentException.class, () -> ClientIdentities.of(Map.of(
                    ClientIdentities.SPIFFE, "true", ClientIdentities.CERTIFICATE,
                    "/etc/tls/client.crt")));
        }
    }

    /** Two workloads, mutual TLS with JSSE: the bundle is the trust, the SPIFFE ID the name. */
    @Test
    void workloadsTrustEachOtherByTheirSpiffeIds() throws Exception {
        try (FakeWorkloadApi agent = new FakeWorkloadApi(socket("mtls"),
                () -> first.answer(ORDERS))) {
            String base = "socket=unix://" + agent.socket();
            SSLContext server = SeclumeKeys.spiffeSslContext(base + "&peer-ids=" + ORDERS);
            SSLContext client = SeclumeKeys.spiffeSslContext(base);
            assertEquals(ORDERS, SpiffeTrustManager.spiffeId(mutual(server, client)));

            SSLContext picky = SeclumeKeys.spiffeSslContext(base + "&peer-ids=" + PAYMENTS);
            assertThrows(Exception.class, () -> mutual(picky, client),
                    "a peer with another SPIFFE ID was let in");
        }
    }

    /** A rotated SVID is taken up; the same one again is not a renewal. */
    @Test
    void aRotatedSvidIsTakenUp() throws Exception {
        AtomicReference<Svid> current = new AtomicReference<>(first);
        try (FakeWorkloadApi agent = new FakeWorkloadApi(socket("rotate"),
                () -> current.get().answer(ORDERS))) {
            try (SpiffeKeyManager manager = assertInstanceOf(SpiffeKeyManager.class,
                    SeclumeKeys.spiffeKeyManager("socket=unix://" + agent.socket()))) {
                X509Certificate before = manager.getCertificateChain("seclume")[0];
                assertFalse(manager.renewNow(), "the same SVID counted as new");
                assertEquals(1, manager.generations());
                current.set(second);
                assertTrue(manager.renewNow());
                assertEquals(2, manager.generations());
                assertNotEquals(before.getSerialNumber(),
                        manager.getCertificateChain("seclume")[0].getSerialNumber());
                ManagedCertificate listed = SeclumeKeys.managedCertificates().stream()
                        .filter(c -> c.kind().equals("spiffe") && c.generations() == 2)
                        .findFirst().orElseThrow();
                assertEquals(ORDERS, listed.name(), "an SVID with no name is its SPIFFE ID");
            }
        }
    }

    /**
     * {@link SeclumeKeys#spiffe}: the key and the trust manager as factories -
     * as a Spring SSL bundle takes them - from one answer of the agent, listed
     * under the name they were given.
     */
    @Test
    void theFactoriesShareOneSvidUnderTheirName() throws Exception {
        try (FakeWorkloadApi agent = new FakeWorkloadApi(socket("named"),
                () -> payments.answer(PAYMENTS))) {
            SeclumeKeys.Spiffe parts = SeclumeKeys.spiffe("socket=unix://" + agent.socket()
                    + "&name=payments-mesh&peer-ids=" + PAYMENTS);
            assertEquals(1, agent.calls(), "the key and the trust asked the agent apart");
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(parts.keys().getKeyManagers(), parts.trust().getTrustManagers(), null);
            assertEquals(PAYMENTS, SpiffeTrustManager.spiffeId(mutual(context, context)));
            assertTrue(SeclumeKeys.managedCertificates().stream().anyMatch(c ->
                    c.kind().equals("spiffe") && c.name().equals("payments-mesh")),
                    SeclumeKeys.managedCertificates().toString());
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

    /** One connection between two SPIFFE contexts; what the server saw. */
    private static X509Certificate mutual(SSLContext server, SSLContext client) throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) server.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            listener.setNeedClientAuth(true);
            CompletableFuture<X509Certificate> peer = CompletableFuture.supplyAsync(() -> {
                try (SSLSocket accepted = (SSLSocket) listener.accept()) {
                    accepted.startHandshake();
                    X509Certificate seen = (X509Certificate) accepted.getSession()
                            .getPeerCertificates()[0];
                    accepted.getOutputStream().write(1);
                    accepted.getOutputStream().flush();
                    return seen;
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            });
            try (SSLSocket socket = (SSLSocket) client.getSocketFactory().createSocket(
                    InetAddress.getLoopbackAddress(), listener.getLocalPort())) {
                socket.startHandshake();
                if (socket.getInputStream().read() != 1) {
                    throw new SSLHandshakeException("the server refused");
                }
            }
            return peer.get(30, TimeUnit.SECONDS);
        }
    }
}
