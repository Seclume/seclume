package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Random;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.SeclumeSslEngine;
import space.seclume.internal.TrustChoice;
import space.seclume.secret.SecretScope;

/**
 * seclume's TLS as an {@link SSLEngine}, against the JDK's engine as the
 * server - driven the way Kafka and Netty drive an engine: wrap and unwrap on
 * byte buffers, nothing else.
 */
@Timeout(120)
class SeclumeSslEngineTest {

    private static final String HOSTNAME = "broker.example.com";
    private static TestCertificates certificates;
    private static SSLContext serverContext;
    private static TrustChoice.Choice trust;

    @TempDir
    static Path dir;

    @BeforeAll
    static void anAuthority() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issue("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(server.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        serverContext = SSLContext.getInstance("TLSv1.3");
        serverContext.init(keys.getKeyManagers(), null, null);
        KeyStore anchors = certificates.trustStore();
        StringBuilder pem = new StringBuilder();
        for (String alias : Collections.list(anchors.aliases())) {
            Certificate ca = anchors.getCertificate(alias);
            pem.append("-----BEGIN CERTIFICATE-----\n")
                    .append(Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                            .encodeToString(ca.getEncoded()))
                    .append("\n-----END CERTIFICATE-----\n");
        }
        Path ca = Files.writeString(dir.resolve("ca.pem"), pem);
        trust = TrustChoice.of("jdbc:x://h/db?tlsRootCert="
                + ca.toString().replace('\\', '/'), null);
    }

    @AfterAll
    static void removeTheAuthority() throws Exception {
        if (certificates != null) {
            certificates.close();
        }
    }

    @Test
    void handshakesAndCarriesDataBothWays() throws Exception {
        Pair pair = new Pair(new SeclumeSslEngine(HOSTNAME, 9093, trust, null));
        pair.handshake();
        assertEquals("TLSv1.3", pair.client.getSession().getProtocol());
        assertTrue(pair.client.getSession().getCipherSuite().startsWith("TLS_AES_"),
                pair.client.getSession().getCipherSuite());
        assertTrue(pair.client.getSession().getPeerPrincipal().getName().contains("server"));

        byte[] hello = "hello, broker".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(hello, pair.clientToServer(hello));
        byte[] answer = "hello, client".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(answer, pair.serverToClient(answer));
    }

    @Test
    void carriesMoreThanOneRecordEachWay() throws Exception {
        Pair pair = new Pair(new SeclumeSslEngine(HOSTNAME, 9093, trust, null));
        pair.handshake();
        byte[] big = new byte[100_000];
        new Random(7).nextBytes(big);
        assertArrayEquals(big, pair.clientToServer(big));
        assertArrayEquals(big, pair.serverToClient(big));
    }

    @Test
    void aPlaceholderIsReplacedOnItsWayIntoTheCipher() throws Exception {
        byte[] secret = "the-real-password".getBytes(StandardCharsets.US_ASCII);
        byte[] placeholder = "PLACEHOLDER".getBytes(StandardCharsets.US_ASCII);
        SeclumeSslEngine.Outgoing replacing = plain -> {
            int at = indexOf(plain, placeholder);
            if (at < 0) {
                return SeclumeSslEngine.Outgoing.Step.unchanged(
                        Math.min(plain.remaining(), SeclumeSslEngine.MAX_PLAINTEXT));
            }
            if (at > plain.position()) {
                return SeclumeSslEngine.Outgoing.Step.unchanged(at - plain.position());
            }
            SecretScope bytes = SecretScope.allocate(secret.length);
            MemorySegment.copy(secret, 0, bytes.segment(), ValueLayout.JAVA_BYTE, 0,
                    secret.length);
            bytes.length(secret.length);
            return SeclumeSslEngine.Outgoing.Step.replace(placeholder.length, bytes);
        };
        Pair pair = new Pair(new SeclumeSslEngine(HOSTNAME, 9093, trust, replacing));
        pair.handshake();
        byte[] sent = "AUTH orders PLACEHOLDER\r\n".getBytes(StandardCharsets.US_ASCII);
        assertEquals("AUTH orders the-real-password\r\n",
                new String(pair.clientToServer(sent, 31), StandardCharsets.US_ASCII));
    }

    @Test
    void aCertificateForAnotherNameIsRefused() throws Exception {
        Pair pair = new Pair(new SeclumeSslEngine("other.example.com", 9093, trust, null));
        SSLException refused = assertThrows(SSLException.class, pair::handshake);
        assertTrue(refused.getMessage().contains("other.example.com"), refused.getMessage());
    }

    @Test
    void anAuthorityTheJvmDoesNotKnowIsRefused() throws Exception {
        Pair pair = new Pair(new SeclumeSslEngine(HOSTNAME, 9093, null, null));
        assertThrows(SSLException.class, pair::handshake);
    }

    @Test
    void closingSendsCloseNotify() throws Exception {
        Pair pair = new Pair(new SeclumeSslEngine(HOSTNAME, 9093, trust, null));
        pair.handshake();
        pair.client.closeOutbound();
        ByteBuffer out = ByteBuffer.allocate(pair.client.getSession().getPacketBufferSize());
        SSLEngineResult result = pair.client.wrap(ByteBuffer.allocate(0), out);
        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus());
        assertTrue(result.bytesProduced() > 0);
        assertTrue(pair.client.isOutboundDone());
        out.flip();
        SSLEngineResult atServer = pair.server.unwrap(out, ByteBuffer.allocate(1 << 15));
        assertEquals(SSLEngineResult.Status.CLOSED, atServer.getStatus());
    }

    private static int indexOf(ByteBuffer in, byte[] what) {
        outer:
        for (int i = in.position(); i <= in.limit() - what.length; i++) {
            for (int j = 0; j < what.length; j++) {
                if (in.get(i + j) != what[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** A client engine and the JDK's server engine, joined by two buffers. */
    private static final class Pair {

        final SSLEngine client;
        final SSLEngine server;
        final ByteBuffer toServer = ByteBuffer.allocate(1 << 17);
        final ByteBuffer toClient = ByteBuffer.allocate(1 << 17);
        final ByteBuffer serverApp = ByteBuffer.allocate(1 << 15);
        final ByteBuffer clientApp = ByteBuffer.allocate(1 << 15);

        Pair(SSLEngine client) {
            this.client = client;
            this.server = serverContext.createSSLEngine();
            server.setUseClientMode(false);
        }

        void handshake() throws Exception {
            client.beginHandshake();
            server.beginHandshake();
            for (int i = 0; i < 100; i++) {
                boolean clientDone = step(client, toServer, toClient, clientApp);
                boolean serverDone = step(server, toClient, toServer, serverApp);
                if (clientDone && serverDone) {
                    return;
                }
            }
            throw new AssertionError("the handshake did not finish: client "
                    + client.getHandshakeStatus() + ", server " + server.getHandshakeStatus());
        }

        /** One move of one side; true when it is not handshaking any more. */
        private static boolean step(SSLEngine engine, ByteBuffer out, ByteBuffer in,
                                    ByteBuffer app) throws Exception {
            HandshakeStatus status = engine.getHandshakeStatus();
            switch (status) {
                case NEED_WRAP -> engine.wrap(ByteBuffer.allocate(0), out);
                case NEED_UNWRAP, NEED_UNWRAP_AGAIN -> {
                    in.flip();
                    engine.unwrap(in, app);
                    in.compact();
                }
                case NEED_TASK -> {
                    for (Runnable task; (task = engine.getDelegatedTask()) != null; ) {
                        task.run();
                    }
                }
                default -> {
                    return true;
                }
            }
            return engine.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING
                    || engine.getHandshakeStatus() == HandshakeStatus.FINISHED;
        }

        byte[] clientToServer(byte[] data) throws Exception {
            return clientToServer(data, data.length);
        }

        /** Sends {@code data} from the client; what the server reads, {@code expect} bytes. */
        byte[] clientToServer(byte[] data, int expect) throws Exception {
            return carry(client, server, toServer, serverApp, data, expect);
        }

        byte[] serverToClient(byte[] data) throws Exception {
            return carry(server, client, toClient, clientApp, data, data.length);
        }

        private static byte[] carry(SSLEngine from, SSLEngine to, ByteBuffer net, ByteBuffer app,
                                    byte[] data, int expect) throws Exception {
            ByteBuffer src = ByteBuffer.wrap(data);
            ByteArrayOutputStream received = new ByteArrayOutputStream();
            for (int i = 0; i < 10_000 && received.size() < expect; i++) {
                if (src.hasRemaining() && net.remaining() > 20_000) {
                    SSLEngineResult wrapped = from.wrap(src, net);
                    assertEquals(SSLEngineResult.Status.OK, wrapped.getStatus());
                }
                net.flip();
                SSLEngineResult unwrapped = to.unwrap(net, app);
                net.compact();
                app.flip();
                byte[] got = new byte[app.remaining()];
                app.get(got);
                received.write(got);
                app.clear();
                if (unwrapped.getStatus() == SSLEngineResult.Status.CLOSED) {
                    break;
                }
            }
            return received.toByteArray();
        }
    }
}
