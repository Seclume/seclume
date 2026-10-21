package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.Transport;
import space.seclume.secret.SecretScope;
import space.seclume.tls.ScriptedTlsServer.Outgoing;

/**
 * A freeze while another thread is inside {@code read}.
 *
 * <p>{@link TlsConnection#freeze} deliberately does not wait for a reader
 * blocked on the peer, so a read that started before the freeze goes on after
 * it. Whatever that read takes in, it must not <b>write</b>: the frozen write
 * state - key and sequence number - now belongs to whoever thaws it, and a
 * record sent here with it is a record the thawed connection sends again under
 * the same AES-GCM nonce. Until 20.10.2026 a KeyUpdate asking for an answer,
 * arriving to such a read, was answered from here.
 */
@Timeout(60)
class FrozenWhileReadingTest {

    private static final String HOSTNAME = "localhost";

    private static TestCertificates certificates;
    private static byte[] leaf;
    private static PrivateKey key;

    @BeforeAll
    static void issueAServerCertificate() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issueEc("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        leaf = server.certificate().getEncoded();
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(server.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        key = (PrivateKey) store.getKey("server", TestCertificates.PASSWORD.toCharArray());
    }

    @AfterAll
    static void removeTheAuthority() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    @Test
    void aKeyUpdateArrivingAfterTheFreezeIsNotAnsweredFromHere() throws Exception {
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, leaf, key,
                false, null, List.of(Outgoing.keyUpdate(1)));
        Gate gate = new Gate(server);
        TlsConnection connection = ClientHandshake.connectWithoutAuthenticating(gate, HOSTNAME);
        try (SecretScope frozen = SecretScope.allocate(512)) {
            ByteBuffer greeting = ByteBuffer.allocate(ScriptedTlsServer.GREETING.length);
            while (greeting.hasRemaining()) {
                assertTrue(connection.read(greeting) >= 0, "the greeting did not arrive");
            }
            assertArrayEquals(ScriptedTlsServer.GREETING, greeting.array());

            gate.shut();
            AtomicReference<Throwable> ended = new AtomicReference<>();
            Thread reader = new Thread(() -> {
                try {
                    connection.read(ByteBuffer.allocate(64));
                } catch (Throwable e) {
                    ended.set(e);
                }
            }, "reader");
            reader.start();
            assertTrue(gate.waiting.await(10, TimeUnit.SECONDS), "the read never reached the peer");

            connection.freeze(frozen.segment(), 0);
            gate.release();
            reader.join(10_000);
            assertTrue(!reader.isAlive(), "the read did not end");

            assertEquals(List.of(), server.clientMessagesAfterFinished(),
                    "a record went out under the frozen write state");
            assertTrue(ended.get() instanceof IOException,
                    "the read ended with " + ended.get());
        } finally {
            connection.close();
        }
        assertTrue(server.isOpen(), "the frozen connection closed the transport it handed on");
    }

    /** The server behind a gate that a read waits at once it is closed. */
    private static final class Gate implements Transport {
        private final Transport inner;
        private final CountDownLatch released = new CountDownLatch(1);
        final CountDownLatch waiting = new CountDownLatch(1);
        private volatile boolean shut;

        Gate(Transport inner) {
            this.inner = inner;
        }

        void shut() {
            shut = true;
        }

        void release() {
            released.countDown();
        }

        @Override
        public int read(ByteBuffer into) throws IOException {
            if (shut) {
                waiting.countDown();
                try {
                    released.await();
                } catch (InterruptedException e) {
                    throw new IOException(e);
                }
            }
            return inner.read(into);
        }

        @Override
        public int write(ByteBuffer from) throws IOException {
            return inner.write(from);
        }

        @Override
        public boolean isOpen() {
            return inner.isOpen();
        }

        @Override
        public void close() {
            inner.close();
        }
    }
}
