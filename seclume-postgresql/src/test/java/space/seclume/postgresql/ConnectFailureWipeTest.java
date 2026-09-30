package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * A login that goes wrong still leaves no password behind.
 *
 * <p>{@code space.seclume.secret.WipeOnFailureTest} shows the same thing one
 * layer down, with the failures handed in by the test. This one has a socket,
 * so the failures are the ones a server actually produces: it rejects the
 * password, it hangs up halfway through, it stops answering. Between the two
 * there is no gap left where the wipe could be attached to the happy path only.
 *
 * <p>Measured with {@link SecretScope#open()}: after a failed connect it has to
 * be back where it started. Two of the tests additionally check
 * {@link SecretScope#allocations()}, and for opposite reasons - for a rejected
 * password the counter <b>must</b> have moved, or the test proved nothing but
 * that an early error skips the login; for a refused TLS handshake it must
 * <b>not</b> have moved, because a connection that never became private has no
 * business reading a secret at all.
 *
 * <p>No database is needed. The server is forty lines of {@code ServerSocket}
 * speaking just enough of the protocol to get to the interesting moment.
 */
@org.junit.jupiter.api.parallel.Isolated
class ConnectFailureWipeTest {

    private static final String PASSWORD = "hunter2-hunter2";
    private static final int CLEARTEXT = 3;

    /** What the fake server does once a client has connected. */
    @FunctionalInterface
    private interface Behaviour {
        void serve(DataInputStream in, OutputStream out, Socket socket) throws Exception;
    }

    /** One connection, one behaviour, and the port it can be reached at. */
    private static final class FakeServer implements AutoCloseable {

        private final ServerSocket listener;
        private final Thread thread;
        private final CountDownLatch connected = new CountDownLatch(1);
        private final AtomicReference<Exception> failure = new AtomicReference<>();

        FakeServer(Behaviour behaviour) throws IOException {
            this.listener = new ServerSocket();
            this.listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            this.thread = new Thread(() -> {
                try (Socket socket = listener.accept()) {
                    connected.countDown();
                    behaviour.serve(new DataInputStream(socket.getInputStream()),
                            socket.getOutputStream(), socket);
                } catch (Exception e) {
                    failure.set(e);
                } finally {
                    connected.countDown();
                }
            }, "fake-postgres");
            this.thread.setDaemon(true);
            this.thread.start();
        }

        int port() {
            return listener.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            listener.close();
            thread.interrupt();
            try {
                thread.join(TimeUnit.SECONDS.toMillis(5));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    // ------------------------------------------------------ the protocol --

    /** Reads the untagged startup message and throws it away. */
    private static void readStartup(DataInputStream in) throws IOException {
        int length = in.readInt();
        in.readNBytes(length - 4);
    }

    /** Reads one tagged message and returns its tag. */
    private static byte readMessage(DataInputStream in) throws IOException {
        byte tag = in.readByte();
        int length = in.readInt();
        in.readNBytes(length - 4);
        return tag;
    }

    private static void sendCleartextRequest(OutputStream out) throws IOException {
        out.write('R');
        writeInt(out, 8);
        writeInt(out, CLEARTEXT);
        out.flush();
    }

    /** ErrorResponse: severity, SQLSTATE, message, then the terminator. */
    private static void sendError(OutputStream out, String sqlState, String message)
            throws IOException {
        byte[] body = ("S" + "FATAL\0" + "C" + sqlState + "\0"
                + "M" + message + "\0" + "\0").getBytes(StandardCharsets.UTF_8);
        out.write('E');
        writeInt(out, 4 + body.length);
        out.write(body);
        out.flush();
    }

    private static void writeInt(OutputStream out, int value) throws IOException {
        out.write((value >>> 24) & 0xff);
        out.write((value >>> 16) & 0xff);
        out.write((value >>> 8) & 0xff);
        out.write(value & 0xff);
    }

    private static SecretProvider password() {
        return new CallbackSecretProvider(64, target -> {
            byte[] bytes = PASSWORD.getBytes(StandardCharsets.US_ASCII);
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
    }

    private static PgSession.Settings settings(int port, TlsMode tls) {
        return new PgSession.Settings("127.0.0.1", port, "app", "app", password(),
                "seclume-test", 5_000, HostList.of("127.0.0.1", port), ResultLimit.NONE, tls);
    }

    // ---------------------------------------------------------- the cases --

    /**
     * The commonest failure there is: the password is wrong.
     *
     * <p>The secret has been read, sent and rejected - the exception arrives
     * with the scope still open and unwinds through it.
     */
    @Test
    void aRejectedPasswordWipesIt() throws Exception {
        long open = SecretScope.open();
        long read = SecretScope.allocations();

        try (FakeServer server = new FakeServer((in, out, socket) -> {
            readStartup(in);
            sendCleartextRequest(out);
            assertEquals((byte) 'p', readMessage(in), "the driver should send a password");
            sendError(out, "28P01", "password authentication failed for user \"app\"");
        })) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> PgSession.open(settings(server.port(), TlsMode.OFF)));
            assertTrue(refused.getMessage().contains("password authentication failed"),
                    refused.getMessage());
        }

        assertTrue(SecretScope.allocations() > read,
                "the login never got as far as reading the secret - then this proves nothing");
        assertEquals(open, SecretScope.open());
    }

    /**
     * A server that plays SCRAM up to the client's proof and then says OK
     * without its own final message - it never proved it knows the password.
     * A server that does that may not be the database, and is refused.
     */
    @Test
    void anOkWithoutTheScramServerSignatureIsRefused() throws Exception {
        long open = SecretScope.open();
        try (FakeServer server = new FakeServer((in, out, socket) -> {
            readStartup(in);
            byte[] mechanism = "SCRAM-SHA-256\0\0".getBytes(StandardCharsets.US_ASCII);
            out.write('R');
            writeInt(out, 8 + mechanism.length);
            writeInt(out, 10);                                   // AuthenticationSASL
            out.write(mechanism);
            out.flush();
            String first = saslPayload(in);                       // n,,n=,r=<nonce>
            String nonce = first.substring(first.indexOf("r=") + 2);
            byte[] serverFirst = ("r=" + nonce + "server,s="
                    + java.util.Base64.getEncoder().encodeToString(new byte[16]) + ",i=4096")
                    .getBytes(StandardCharsets.US_ASCII);
            out.write('R');
            writeInt(out, 8 + serverFirst.length);
            writeInt(out, 11);                                   // SASLContinue
            out.write(serverFirst);
            out.flush();
            readMessage(in);                                      // the client's proof
            out.write('R');
            writeInt(out, 8);
            writeInt(out, 0);                                    // OK, and no SASLFinal
            out.flush();
            in.read();
        })) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> PgSession.open(settings(server.port(), TlsMode.OFF)));
            assertEquals("28000", refused.getSQLState(), refused.getMessage());
            assertTrue(refused.getMessage().contains("never proved"), refused.getMessage());
        }
        assertEquals(open, SecretScope.open());
    }

    /** The SASLInitialResponse's data: mechanism name, then a length, then the data. */
    private static String saslPayload(DataInputStream in) throws IOException {
        byte tag = in.readByte();
        assertEquals((byte) 'p', tag);
        int length = in.readInt();
        byte[] body = in.readNBytes(length - 4);
        int at = 0;
        while (body[at] != 0) {
            at++;
        }
        int dataLength = java.nio.ByteBuffer.wrap(body, at + 1, 4).getInt();
        return new String(body, at + 5, dataLength, StandardCharsets.US_ASCII);
    }

    /**
     * PostgreSQL 18 asking for an OAuth token on a connection without TLS: a
     * bearer token is a password anyone who reads it can use, so the driver
     * refuses before it reads the token or sends a byte of it.
     */
    @Test
    void anOAuthTokenIsNeverSentUnencrypted() throws Exception {
        long open = SecretScope.open();
        AtomicReference<Integer> sentAfterwards = new AtomicReference<>();
        try (FakeServer server = new FakeServer((in, out, socket) -> {
            readStartup(in);
            byte[] mechanism = "OAUTHBEARER\0\0".getBytes(StandardCharsets.US_ASCII);
            out.write('R');
            writeInt(out, 8 + mechanism.length);
            writeInt(out, 10);                                   // AuthenticationSASL
            out.write(mechanism);
            out.flush();
            sentAfterwards.set(in.read());                       // -1: nothing but the hang-up
        })) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> PgSession.open(settings(server.port(), TlsMode.OFF)));
            assertEquals("28000", refused.getSQLState(), refused.getMessage());
            assertTrue(refused.getMessage().contains("OAUTHBEARER"), refused.getMessage());
            server.connected.await(5, TimeUnit.SECONDS);
            server.thread.join(5_000);
        }
        Integer next = sentAfterwards.get();
        assertTrue(next == null || next == -1 || next == 'X',
                "after the refusal the driver sent 0x" + Integer.toHexString(next));
        assertEquals(open, SecretScope.open());
    }

    /**
     * The server hangs up while the password is in flight.
     *
     * <p>Not an orderly error but an {@code IOException} out of the middle of
     * the exchange - a different exit from the one above, through a different
     * catch, and the interesting one because there is no protocol left to be
     * polite with.
     */
    @Test
    void aConnectionDroppedMidLoginWipesIt() throws Exception {
        long open = SecretScope.open();
        long read = SecretScope.allocations();

        try (FakeServer server = new FakeServer((in, out, socket) -> {
            readStartup(in);
            sendCleartextRequest(out);
            socket.setSoLinger(true, 0); // RST rather than a polite FIN
            socket.close();
        })) {
            assertThrows(SQLException.class,
                    () -> PgSession.open(settings(server.port(), TlsMode.OFF)));
        }

        assertTrue(SecretScope.allocations() > read, "the secret was never read");
        assertEquals(open, SecretScope.open());
    }

    /**
     * The server says nothing at all and the thread is interrupted.
     *
     * <p>This is cancellation as it really happens: a pool shutting down, a
     * request that gave up, a container being stopped. The worker is blocked in
     * a socket read with the password beside it, and the wipe has to survive
     * being cut off there.
     */
    @Test
    void anInterruptedLoginWipesIt() throws Exception {
        long open = SecretScope.open();
        CountDownLatch reading = new CountDownLatch(1);

        try (FakeServer server = new FakeServer((in, out, socket) -> {
            readStartup(in);
            sendCleartextRequest(out);
            reading.countDown();
            // Nothing else, ever. The client is now waiting for an answer.
            Thread.sleep(TimeUnit.SECONDS.toMillis(30));
        })) {
            AtomicReference<Throwable> thrown = new AtomicReference<>();
            Thread worker = new Thread(() -> {
                try {
                    PgSession.open(settings(server.port(), TlsMode.OFF));
                } catch (Throwable t) {
                    thrown.set(t);
                }
            }, "interrupted-login");
            worker.start();

            assertTrue(reading.await(10, TimeUnit.SECONDS), "the server never got that far");
            // The password has been sent by now and the driver is blocked
            // waiting for the verdict, which is exactly where the interrupt
            // has to land.
            Thread.sleep(200);
            worker.interrupt();
            worker.join(TimeUnit.SECONDS.toMillis(10));

            assertTrue(!worker.isAlive(), "the interrupt did not get through");
            assertNotNull(thrown.get(), "an interrupted login has to fail, not return");
        }

        assertEquals(open, SecretScope.open());
    }

    /**
     * TLS was required and the server does not offer it - and the secret is
     * never even asked for.
     *
     * <p>The other tests ask whether the wipe happened. This one asks something
     * stronger and cheaper: on a connection that never became private, the
     * secret source must not be touched at all. A driver that read the password
     * first and checked the transport afterwards would have had it in memory
     * for no reason, and would have asked a Vault or a smartcard for it.
     */
    @Test
    void aRefusedTlsHandshakeNeverReachesTheSecret() throws Exception {
        long open = SecretScope.open();
        long read = SecretScope.allocations();

        try (FakeServer server = new FakeServer((in, out, socket) -> {
            // The eight-byte SSLRequest, answered with a flat no.
            in.readInt();
            in.readInt();
            out.write('N');
            out.flush();
            // Give the client its moment to give up before the socket goes.
            Thread.sleep(500);
        })) {
            SQLException refused = assertThrows(SQLException.class,
                    () -> PgSession.open(settings(server.port(), TlsMode.REQUIRE)));
            assertTrue(refused.getMessage().contains("does not offer TLS"), refused.getMessage());
        }

        assertEquals(read, SecretScope.allocations(),
                "the secret was read although the connection was never encrypted");
        assertEquals(open, SecretScope.open());
    }
}
