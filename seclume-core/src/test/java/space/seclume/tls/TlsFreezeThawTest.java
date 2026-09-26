package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.Transport;
import space.seclume.secret.SecretScope;

/**
 * Milestone 5 for the TLS half: a connection written down, handed to a
 * different object, and carried on - <b>while the peer keeps talking to it
 * without noticing anything happened</b>.
 *
 * <p>That last part is what is actually being tested, and why the peer is
 * JSSE rather than something from this repository. The server holds its own
 * keys and its own record counters; it was never told that the client it
 * started talking to no longer exists. If a traffic secret or a sequence
 * number did not survive being written down, the next record fails its tag
 * and the conversation stops - there is no way for this to pass by
 * accident.
 *
 * <p>Only the TLS half is written down here; the socket underneath stays the
 * same one. The two are separate on purpose, because they are separate
 * layers: what the record layer knows is not what the socket knows, and a
 * format that mixed them could be right about neither on its own.
 */
@Timeout(120)
class TlsFreezeThawTest {

    private static final String HOSTNAME = "db.example.com";

    private static TestCertificates certificates;
    private static SSLContext serverContext;
    private static KeyStore trustStore;

    @BeforeAll
    static void startAnAuthorityAndAServerIdentity() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        certificates = TestCertificates.generate();
        TestCertificates.Issued server = certificates.issue("server",
                "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
        trustStore = certificates.trustStore();
        serverContext = contextPresenting(server.keystore());
    }

    @AfterAll
    static void removeTheAuthority() throws IOException {
        if (certificates != null) {
            certificates.close();
        }
    }

    @Test
    void aConnectionSurvivesBeingWrittenDownAndPickedUpAgain() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext);
                Transport socket = connectTo(server);
                // The frozen form is key material, so it goes where key material goes.
                SecretScope frozen = SecretScope.allocate(512)) {

            int length;
            // Several exchanges first, so that both sequence counters are well
            // past zero - a migration that silently restarted them would still
            // pass if this froze immediately after the handshake.
            TlsConnection before = ClientHandshake.connect(socket, HOSTNAME,
                    CertificateTrust.of(trustStore));
            try {
                for (int i = 0; i < 5; i++) {
                    echo(before, "round " + i);
                }
                length = before.freeze(frozen.segment(), 0);
                assertTrue(length > 0);
            } finally {
                before.close();       // releases this object; must not touch the socket or the peer
            }

            TlsConnection after = TlsConnection.thaw(socket, frozen.segment(), 0, length);
            try {
                echo(after, "after the move");
                echo(after, "and again");
            } finally {
                after.close();
            }
            assertTrue(server.failure() == null || server.failure() instanceof java.io.EOFException
                            || server.failure().getMessage() == null
                            || !server.failure().getMessage().contains("bad_record_mac"),
                    "the server rejected a record: " + server.failure());
        }
    }

    /**
     * Freezing is not closing: the peer is told nothing, so the socket has to
     * survive it. Shown by the connection continuing to work afterwards, and
     * by the frozen object itself refusing to be used.
     */
    @Test
    void theFrozenConnectionRefusesToBeUsedAndLeavesTheSocketAlone() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext);
                Transport socket = connectTo(server);
                SecretScope frozen = SecretScope.allocate(512)) {

            TlsConnection before = ClientHandshake.connect(socket, HOSTNAME,
                    CertificateTrust.of(trustStore));
            echo(before, "before");
            int length = before.freeze(frozen.segment(), 0);

            assertThrows(IOException.class,
                    () -> before.write(ByteBuffer.wrap("no".getBytes(StandardCharsets.US_ASCII))),
                    "a frozen connection must not send anything - the peer's counters have moved on");
            assertThrows(IllegalStateException.class, () -> before.freeze(frozen.segment(), 0),
                    "freezing twice would hand the same connection to two owners");
            before.close();

            assertTrue(socket.isOpen(), "closing a frozen connection must leave the socket to "
                    + "whoever continues it");
            try (TlsConnection after = TlsConnection.thaw(socket, frozen.segment(), 0, length)) {
                echo(after, "after");
            }
        }
    }

    /**
     * A snapshot writes what freeze writes and gives nothing up: the
     * connection goes on, a snapshot taken at the same quiet moment is
     * byte for byte the frozen state, and a connection taken up from one
     * carries on as a thawed one does.
     */
    @Test
    void aSnapshotIsTheFrozenStateWithoutGivingTheConnectionUp() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext);
                Transport socket = connectTo(server);
                SecretScope early = SecretScope.allocate(512);
                SecretScope late = SecretScope.allocate(512);
                SecretScope frozen = SecretScope.allocate(512)) {

            TlsConnection before = ClientHandshake.connect(socket, HOSTNAME,
                    CertificateTrust.of(trustStore));
            echo(before, "one");
            int earlyLength = before.snapshot(early.segment(), 0);
            // While the early copy could still be thawed, a record from here
            // would share its nonce with the copy's first one: refused.
            assertThrows(IOException.class,
                    () -> before.write(ByteBuffer.wrap(new byte[] {1})));
            before.snapshotReleased();                      // the early copy is discarded
            echo(before, "still working after a snapshot");
            int lateLength = before.snapshot(late.segment(), 0);
            int frozenLength = before.freeze(frozen.segment(), 0);
            before.close();

            assertEquals(frozenLength, lateLength);
            assertArrayEquals(frozen.segment().asSlice(0, frozenLength).toArray(
                            java.lang.foreign.ValueLayout.JAVA_BYTE),
                    late.segment().asSlice(0, lateLength).toArray(
                            java.lang.foreign.ValueLayout.JAVA_BYTE),
                    "a snapshot at the same moment is not the frozen state");
            assertFalse(java.util.Arrays.equals(
                            early.segment().asSlice(0, earlyLength).toArray(
                                    java.lang.foreign.ValueLayout.JAVA_BYTE),
                            late.segment().asSlice(0, lateLength).toArray(
                                    java.lang.foreign.ValueLayout.JAVA_BYTE)),
                    "the record counters did not move - an old snapshot would pass for new");

            try (TlsConnection after = TlsConnection.thaw(socket, late.segment(), 0, lateLength)) {
                echo(after, "from the snapshot");
            }
        }
    }

    /**
     * Freezing with bytes still unread would drop them silently - the peer
     * believes they arrived and nothing would ever ask again. Refused.
     */
    @Test
    void freezingWithUnreadBytesIsRefused() throws Exception {
        try (EchoServer server = EchoServer.start(serverContext);
                Transport socket = connectTo(server);
                SecretScope frozen = SecretScope.allocate(512);
                TlsConnection tls = ClientHandshake.connect(socket, HOSTNAME,
                        CertificateTrust.of(trustStore))) {

            byte[] sent = "twelve bytes".getBytes(StandardCharsets.US_ASCII);
            tls.write(ByteBuffer.wrap(sent));
            ByteBuffer one = ByteBuffer.allocate(1);
            while (one.position() == 0) {
                tls.read(one);                // the whole record is now decrypted, one byte taken
            }

            IllegalStateException refused = assertThrows(IllegalStateException.class,
                    () -> tls.freeze(frozen.segment(), 0));
            assertTrue(refused.getMessage().contains("quiet point"), refused.getMessage());

            readExactly(tls, sent.length - 1);   // drain, then it is allowed
            tls.freeze(frozen.segment(), 0);
        }
    }

    // ---- plumbing ---------------------------------------------------------

    private static void echo(TlsConnection tls, String text) throws IOException {
        byte[] sent = text.getBytes(StandardCharsets.US_ASCII);
        tls.write(ByteBuffer.wrap(sent));
        assertArrayEquals(sent, readExactly(tls, sent.length),
                "the peer answered something else for \"" + text + "\"");
    }

    private static Transport connectTo(EchoServer server) throws IOException {
        return SocketTransport.connect(InetAddress.getLoopbackAddress().getHostAddress(),
                server.port(), 10_000);
    }

    private static byte[] readExactly(TlsConnection tls, int count) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(count);
        while (buffer.hasRemaining()) {
            if (tls.read(buffer) < 0) {
                throw new IOException("the connection ended after "
                        + (count - buffer.remaining()) + " of " + count + " bytes");
            }
        }
        return buffer.array();
    }

    private static SSLContext contextPresenting(Path keystore) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keys.getKeyManagers(), null, null);
        return context;
    }
}
