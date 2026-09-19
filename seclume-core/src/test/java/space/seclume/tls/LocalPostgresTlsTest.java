package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.Transport;

/**
 * Our TLS 1.3 against a real PostgreSQL, carrying a real PostgreSQL
 * conversation - milestone 4 of {@code docs/tls.md}.
 *
 * <p>{@code ClientHandshakeTest} already proves the handshake against JSSE,
 * which is the stricter peer in one way: it verifies our Finished. This
 * proves the other thing, which no amount of loopback can - that a server
 * nobody here configured for us, with its own OpenSSL record layer, its own
 * idea of when to send a session ticket and its own packet boundaries, is
 * talked to successfully by this client.
 *
 * <p>It stops at the first server message rather than logging in. That is
 * deliberate: the point is that an application protocol flows through the
 * encrypted channel in both directions, and PostgreSQL answers a startup
 * message with either an authentication request or an error - both of which
 * are that proof, and neither of which needs a password to arrive. No
 * credential is sent.
 *
 * <p>Opt-in, and it <b>fails</b> rather than skips when a host is named but
 * unreachable - a live test that quietly turns into no test is worse than no
 * test.
 */
@Timeout(60)
class LocalPostgresTlsTest {

    private static final int SSL_REQUEST = 80877103;
    private static final int PROTOCOL_3_0 = 196608;

    @Test
    void ourTlsCarriesAPostgresConversation() throws Exception {
        String host = System.getProperty("seclume.tls.hello.host");
        Assumptions.assumeTrue(host != null && !host.isBlank(), "no TLS fixture configured");
        int port = Integer.getInteger("seclume.tls.pg.port", 5433);

        try (Transport socket = SocketTransport.connect(host, port, 10_000)) {
            assertTrue(requestTls(socket), "the server refused TLS on this port");

            // The fixture's certificate is self-signed and issued for no name this
            // test connects to, so authentication is off here on purpose; what is
            // under test is the handshake and the channel, and the trust half has
            // its own tests against a certificate authority in CertificateTrustTest.
            try (TlsConnection tls = ClientHandshake.connectWithoutAuthenticating(socket, host)) {
                tls.write(ByteBuffer.wrap(startupMessage("seclume_test", "seclume_test")));

                byte[] header = readExactly(tls, 5);
                char type = (char) (header[0] & 0xff);
                int length = ((header[1] & 0xff) << 24) | ((header[2] & 0xff) << 16)
                        | ((header[3] & 0xff) << 8) | (header[4] & 0xff);
                assertTrue(type == 'R' || type == 'E',
                        "PostgreSQL answered with message type '" + type + "', which is neither "
                                + "an authentication request nor an error");
                assertTrue(length >= 4 && length < 1 << 20,
                        "the message length " + length + " is not plausible, so the record was "
                                + "not decrypted correctly");
                byte[] rest = readExactly(tls, length - 4);

                String what = type == 'R'
                        ? "authentication request " + ((rest[0] & 0xff) << 24 | (rest[1] & 0xff) << 16
                                | (rest[2] & 0xff) << 8 | (rest[3] & 0xff))
                        : "error: " + new String(rest, StandardCharsets.UTF_8) // seclume-allow: a server error text
                                .replace('\0', ' ').trim();
                System.err.println("[our TLS -> PostgreSQL] " + host + ":" + port + " answered "
                        + what);
            }
        }
    }

    /** PostgreSQL's pre-TLS handshake: ask, and expect a single 'S'. */
    private static boolean requestTls(Transport socket) throws IOException {
        ByteBuffer request = ByteBuffer.allocate(8).putInt(8).putInt(SSL_REQUEST).flip();
        while (request.hasRemaining()) {
            socket.write(request);
        }
        ByteBuffer answer = ByteBuffer.allocate(1);
        while (answer.hasRemaining()) {
            assertTrue(socket.read(answer) >= 0, "the server closed the connection when asked "
                    + "for TLS");
        }
        return answer.get(0) == 'S';
    }

    private static byte[] startupMessage(String user, String database) {
        byte[] userBytes = user.getBytes(StandardCharsets.UTF_8);       // seclume-allow: a user name
        byte[] databaseBytes = database.getBytes(StandardCharsets.UTF_8); // seclume-allow: a database name
        int length = 4 + 4 + 5 + userBytes.length + 1 + 9 + databaseBytes.length + 1 + 1;
        ByteBuffer out = ByteBuffer.allocate(length);
        out.putInt(length).putInt(PROTOCOL_3_0);
        out.put("user".getBytes(StandardCharsets.US_ASCII)).put((byte) 0);  // seclume-allow: a constant
        out.put(userBytes).put((byte) 0);
        out.put("database".getBytes(StandardCharsets.US_ASCII)).put((byte) 0); // seclume-allow: a constant
        out.put(databaseBytes).put((byte) 0);
        out.put((byte) 0);
        return out.array();
    }

    private static byte[] readExactly(TlsConnection tls, int count) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(count);
        while (buffer.hasRemaining()) {
            int read = tls.read(buffer);
            assertEquals(true, read >= 0, "the connection ended after "
                    + (count - buffer.remaining()) + " of " + count + " bytes");
        }
        return buffer.array();
    }
}
