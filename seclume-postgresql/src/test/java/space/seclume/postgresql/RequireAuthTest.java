package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.EOFException;
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
import java.sql.SQLInvalidAuthorizationSpecException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.postgresql.jdbc.SeclumeDataSource;
import space.seclume.secret.CallbackSecretProvider;

/**
 * {@code requireAuth}: a login method the option does not allow is refused
 * before anything of the answer is sent - against a fake server that asks for
 * exactly that method and records what comes back.
 */
class RequireAuthTest {

    private static final int OK = 0;
    private static final int CLEARTEXT = 3;
    private static final int MD5 = 5;

    @Test
    void theOptionReadsAsLibpqDoes() {
        RequireAuth scram = RequireAuth.of("scram-sha-256");
        assertTrue(scram.allows("scram-sha-256"));
        assertFalse(scram.allows("md5"));
        assertFalse(scram.allows("none"));

        RequireAuth notWeak = RequireAuth.of(" !md5 , !password ");
        assertFalse(notWeak.allows("md5"));
        assertFalse(notWeak.allows("password"));
        assertTrue(notWeak.allows("scram-sha-256"));
        assertTrue(notWeak.allows("none"));

        assertTrue(RequireAuth.of(null).allows("md5"));
        assertTrue(RequireAuth.of(" ").allows("password"));
        assertEquals("scram-sha-256,gss", RequireAuth.of("scram-sha-256,gss").toString());
    }

    @Test
    void whatLibpqRefusesIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> RequireAuth.of("scram-sha-256,!md5"));
        assertThrows(IllegalArgumentException.class, () -> RequireAuth.of("md4"));
        assertThrows(IllegalArgumentException.class, () -> RequireAuth.of("md5,md5"));
        assertThrows(IllegalArgumentException.class, () -> RequireAuth.of("scram-sha-256,"));
        assertThrows(SQLException.class, () -> new SeclumeDataSource().setRequireAuth("kerberos"));
    }

    @Test
    void md5IsRefusedBeforeTheHashLeaves() throws Exception {
        assertRefusedUnanswered(MD5, "scram-sha-256", "md5 authentication");
    }

    @Test
    void thePasswordItselfIsRefusedBeforeItLeaves() throws Exception {
        assertRefusedUnanswered(CLEARTEXT, "!password,!md5", "password authentication");
    }

    @Test
    void aServerThatAsksForNothingIsRefusedWhenAMethodIsRequired() throws Exception {
        assertRefusedUnanswered(OK, "scram-sha-256", "no authentication at all");
    }

    @Test
    void aMethodThatIsAllowedIsAnswered() throws Exception {
        try (ServerSocket listener = listener()) {
            CompletableFuture<Integer> answer = serve(listener, MD5);
            SQLException failed = assertThrows(SQLException.class,
                    // md5 over a line without TLS: allowed here, the question is requireAuth.
                    () -> PgSession.open(settings(listener.getLocalPort(), "!password")
                            .allowingLegacyHash()));
            assertTrue(failed.getMessage().contains("password authentication failed"),
                    failed.getMessage());
            assertEquals('p', answer.get(10, TimeUnit.SECONDS), "the md5 answer was not sent");
        }
    }

    /**
     * md5 is md5(md5(password || user) || salt) for a salt the server chose:
     * a server in the middle of unverified TLS - here, of no TLS - takes the
     * answer and guesses against a fast hash. Refused unless
     * allowLegacyHashOverUnverifiedTls says otherwise, and nothing is sent.
     */
    @Test
    void md5OverAnUnverifiedLineIsRefused() throws Exception {
        try (ServerSocket listener = listener()) {
            CompletableFuture<Integer> answer = serve(listener, MD5);
            SQLException refused = assertThrows(SQLException.class,
                    () -> PgSession.open(settings(listener.getLocalPort(), null)));
            assertEquals("28000", refused.getSQLState(), refused.getMessage());
            assertTrue(refused.getMessage().contains("allowLegacyHashOverUnverifiedTls"),
                    refused.getMessage());
            assertEquals(-1, answer.get(10, TimeUnit.SECONDS), "an md5 answer went out");
        }
    }

    /**
     * A ReadyForQuery in place of any login: it ended the login as a success,
     * so neither requireAuth nor SCRAM's server signature was ever checked -
     * anybody in the middle under tls=prefer was taken for the database.
     */
    @Test
    void aReadyForQueryWithoutAnyLoginIsRefused() throws Exception {
        for (String requireAuth : new String[] {"scram-sha-256", null}) {
            try (ServerSocket listener = listener()) {
                CompletableFuture<Void> served = CompletableFuture.runAsync(() -> {
                    try (Socket socket = listener.accept();
                         DataInputStream in = new DataInputStream(socket.getInputStream())) {
                        OutputStream out = socket.getOutputStream();
                        in.readNBytes(in.readInt() - 4);             // the startup message
                        out.write('Z');
                        writeInt(out, 5);
                        out.write('I');
                        out.flush();
                        in.read();                                   // until the client goes
                    } catch (IOException gone) {
                        // the client hung up - what it should do
                    }
                });
                SQLException refused = assertThrows(SQLException.class,
                        () -> PgSession.open(settings(listener.getLocalPort(), requireAuth)).close(),
                        "requireAuth=" + requireAuth);
                // Refused at the login, not found out later by a statement
                // that times out against a server with nothing behind it.
                assertEquals("28000", refused.getSQLState(), refused.getMessage());
                assertTrue(refused.getMessage().contains("before AuthenticationOk"),
                        refused.getMessage());
                served.get(10, TimeUnit.SECONDS);
            }
        }
    }

    /**
     * SCRAM begun and skipped: the server asks for SCRAM-SHA-256, takes the
     * client's first message and answers ReadyForQuery, twice - never the
     * server's proof. Refused with 28000, and the password's memory is given
     * back: no secret scope is left open after the refusal.
     */
    @Test
    void scramBegunAndSkippedIsRefusedAndTheSecretWiped() throws Exception {
        long before = space.seclume.secret.SecretScope.open();
        try (ServerSocket listener = listener()) {
            CompletableFuture<Boolean> served = CompletableFuture.supplyAsync(() -> {
                try (Socket socket = listener.accept();
                     DataInputStream in = new DataInputStream(socket.getInputStream())) {
                    OutputStream out = socket.getOutputStream();
                    in.readNBytes(in.readInt() - 4);                 // the startup message
                    byte[] mechanisms = "SCRAM-SHA-256\0\0".getBytes(StandardCharsets.US_ASCII);
                    out.write('R');
                    writeInt(out, 8 + mechanisms.length);
                    writeInt(out, 10);                               // AuthenticationSASL
                    out.write(mechanisms);
                    out.flush();
                    if (in.read() != 'p') {
                        return false;
                    }
                    in.readNBytes(in.readInt() - 4);                 // the client-first message
                    for (int i = 0; i < 2; i++) {
                        out.write('Z');
                        writeInt(out, 5);
                        out.write('I');
                    }
                    out.flush();
                    in.read();
                    return true;
                } catch (IOException gone) {
                    return true;
                }
            });
            SQLException refused = assertThrows(SQLException.class,
                    () -> PgSession.open(settings(listener.getLocalPort(), null)).close());
            assertTrue(served.get(10, TimeUnit.SECONDS), "the client sent no SCRAM message");
            assertEquals("28000", refused.getSQLState(), refused.getMessage());
            assertTrue(refused.getMessage().contains("before AuthenticationOk"),
                    refused.getMessage());
        }
        assertEquals(before, space.seclume.secret.SecretScope.open(),
                "a secret scope was left open after the refused login");
    }

    /**
     * Kerberos begun and skipped: the server asks for GSSAPI, takes the first
     * token and then answers ReadyForQuery - or AuthenticationOk - without the
     * reply that proves it is the service the ticket was for. Needs a GSSAPI
     * that makes a first token here; without one the login fails before the
     * skip, and the test says so instead of passing.
     */
    @Test
    void kerberosBegunAndSkippedIsRefused() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(space.seclume.internal.Gssapi.available(),
                "no GSSAPI on this machine");
        for (char skip : new char[] {'Z', 'R'}) {
            try (ServerSocket listener = listener()) {
                CompletableFuture<Boolean> served = CompletableFuture.supplyAsync(() -> {
                    try (Socket socket = listener.accept();
                         DataInputStream in = new DataInputStream(socket.getInputStream())) {
                        OutputStream out = socket.getOutputStream();
                        in.readNBytes(in.readInt() - 4);             // the startup message
                        out.write('R');
                        writeInt(out, 8);
                        writeInt(out, 7);                            // AuthenticationGSS
                        out.flush();
                        if (in.read() != 'p') {
                            return false;                            // no token came
                        }
                        in.readNBytes(in.readInt() - 4);             // the first token
                        if (skip == 'R') {
                            out.write('R');                          // AuthenticationOk
                            writeInt(out, 8);
                            writeInt(out, 0);
                        }
                        for (int i = 0; i < 2; i++) {
                            out.write('Z');
                            writeInt(out, 5);
                            out.write('I');
                        }
                        out.flush();
                        in.read();
                        return true;
                    } catch (IOException gone) {
                        return true;                 // the client hung up - what it should do
                    }
                });
                SQLException refused = assertThrows(SQLException.class,
                        () -> PgSession.open(settings(listener.getLocalPort(), null)).close());
                if (!served.get(10, TimeUnit.SECONDS)) {
                    org.junit.jupiter.api.Assumptions.abort("no first Kerberos token here (no "
                            + "ticket or KDC): " + refused.getMessage());
                }
                assertEquals("28000", refused.getSQLState(), refused.getMessage());
                assertTrue(refused.getMessage().contains(skip == 'Z' ? "before AuthenticationOk"
                        : "before mutual authentication was complete"), refused.getMessage());
            }
        }
    }

    private static void assertRefusedUnanswered(int request, String requireAuth, String says)
            throws Exception {
        try (ServerSocket listener = listener()) {
            CompletableFuture<Integer> answer = serve(listener, request);
            SQLInvalidAuthorizationSpecException refused = assertThrows(
                    SQLInvalidAuthorizationSpecException.class,
                    () -> PgSession.open(settings(listener.getLocalPort(), requireAuth)));
            assertEquals("28000", refused.getSQLState());
            assertTrue(refused.getMessage().contains(says), refused.getMessage());
            assertTrue(refused.getMessage().contains("requireAuth=" + requireAuth),
                    refused.getMessage());
            int next = answer.get(10, TimeUnit.SECONDS);
            assertTrue(next != 'p', "an answer to the login request was sent: " + (char) next);
        }
    }

    private static ServerSocket listener() throws IOException {
        ServerSocket listener = new ServerSocket();
        listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        return listener;
    }

    /**
     * Reads the startup message, sends the one authentication request and
     * returns the tag of whatever the client sends next (-1 for nothing).
     */
    private static CompletableFuture<Integer> serve(ServerSocket listener, int request) {
        return CompletableFuture.supplyAsync(() -> {
            try (Socket socket = listener.accept();
                 DataInputStream in = new DataInputStream(socket.getInputStream())) {
                OutputStream out = socket.getOutputStream();
                in.readNBytes(in.readInt() - 4);                 // the startup message
                out.write('R');
                writeInt(out, request == MD5 ? 12 : 8);
                writeInt(out, request);
                if (request == MD5) {
                    out.write(new byte[] {1, 2, 3, 4});           // the salt
                }
                if (request == OK) {
                    out.write('Z');
                    writeInt(out, 5);
                    out.write('I');
                }
                out.flush();
                int tag;
                try {
                    tag = in.readByte();
                } catch (EOFException closed) {
                    return -1;
                }
                if (tag == 'p') {
                    byte[] body = ("SFATAL\0C28P01\0Mpassword authentication failed\0\0")
                            .getBytes(StandardCharsets.US_ASCII);
                    in.readNBytes(in.readInt() - 4);
                    out.write('E');
                    writeInt(out, 4 + body.length);
                    out.write(body);
                    out.flush();
                }
                return tag;
            } catch (IOException e) {
                return -1;                       // the client hung up: nothing was sent
            }
        });
    }

    private static void writeInt(OutputStream out, int value) throws IOException {
        out.write(new byte[] {(byte) (value >>> 24), (byte) (value >>> 16),
                (byte) (value >>> 8), (byte) value});
    }

    private static PgSession.Settings settings(int port, String requireAuth) {
        return new PgSession.Settings("127.0.0.1", port, "app", "app",
                new CallbackSecretProvider(64, target -> {
                    byte[] bytes = "hunter2-hunter2".getBytes(StandardCharsets.US_ASCII); // seclume-allow: a test password
                    MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
                    return bytes.length;
                }),
                "seclume-test", 5_000, HostList.of("127.0.0.1", port), ResultLimit.NONE,
                TlsMode.OFF, space.seclume.internal.jdbc.TlsStack.AUTO, null, false,
                RequireAuth.of(requireAuth));
    }
}
