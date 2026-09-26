package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.postgresql.PgSession;
import space.seclume.tck.fuzz.HostileTransport;

/**
 * A malformed answer, seen from where an application sits.
 *
 * <p>The session fuzz sweep reported this as a breach and the interesting
 * question was whether it survived the JDBC surface - an internal exception
 * that {@code executeQuery} converts on its way out is a tidiness problem, not
 * a defect. It does not convert it. Nothing in this driver catches
 * {@link space.seclume.internal.WireBuffer.Truncated}, which is an
 * {@code IllegalStateException}, so a server whose message claims more bytes
 * than it sent throws it straight through {@code Statement.executeQuery} -
 * a method whose signature promises {@link SQLException} and nothing else.
 *
 * <p><b>Why that matters more than it looks.</b> An application catches
 * {@code SQLException}: that is the contract, that is what a framework's retry
 * and its connection-health check are written against. An unchecked exception
 * from inside a decoder goes past all of it to whatever generic handler is
 * nearest, is logged as a bug in the application, and leaves a connection in a
 * pool that nobody marked as broken.
 *
 * <p>The stream here is an honest answer with one byte changed: the column
 * count in the {@code RowDescription} says two fields where one was sent.
 * Found by the corpus, kept as a case because a sweep of ten thousand blocks
 * is not a regression test.
 */
@Timeout(60)
class TruncatedAnswerReachesTheApplicationTest {

    private static byte[] message(char type, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(type);
        int length = 4 + body.length;
        out.write((length >> 24) & 0xff);
        out.write((length >> 16) & 0xff);
        out.write((length >> 8) & 0xff);
        out.write(length & 0xff);
        out.writeBytes(body);
        return out.toByteArray();
    }

    /** A description claiming {@code fields} columns while describing one. */
    private static byte[] rowDescription(int fields) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write((fields >> 8) & 0xff);
        body.write(fields & 0xff);
        body.writeBytes("n".getBytes(StandardCharsets.UTF_8));
        body.write(0);
        for (int i = 0; i < 4; i++) {
            body.write(0);                    // table oid
        }
        body.write(0);
        body.write(0);                        // column number
        body.write(0);
        body.write(0);
        body.write(0);
        body.write(25);                       // type oid: text
        body.write(0xff);
        body.write(0xff);                     // type length: variable
        body.write(0xff);
        body.write(0xff);
        body.write(0xff);
        body.write(0xff);                     // type modifier
        body.write(0);
        body.write(0);                        // text format
        return message('T', body.toByteArray());
    }

    private static byte[] answer() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(rowDescription(2));    // two announced, one described
        out.writeBytes(message('C', "SELECT 1\0".getBytes(StandardCharsets.UTF_8)));
        out.writeBytes(message('Z', new byte[] {'I'}));
        return out.toByteArray();
    }

    private static Map<String, String> parameters() {
        return Map.of("client_encoding", "UTF8", "DateStyle", "ISO, MDY",
                "integer_datetimes", "on", "TimeZone", "UTC", "server_version", "18.0");
    }

    /**
     * Through the JDBC surface, which is where the promise is made.
     *
     * <p>Asserted on the type rather than on the message: what an application
     * can do about this depends entirely on whether it is a
     * {@code SQLException}, and nothing else about it matters here.
     */
    @Test
    void aMalformedAnswerArrivesAsASqlException() throws Exception {
        PgSession session = PgSession.resume(HostileTransport.of(answer()),
                parameters(), 1, 2);
        try (Connection connection = PgConnection.resume(session, false);
                Statement statement = connection.createStatement()) {
            SQLException refused = org.junit.jupiter.api.Assertions.assertThrows(
                    SQLException.class, () -> statement.executeQuery("select n from t"));
            System.err.println("[truncated] " + refused.getSQLState()
                    + " " + refused.getMessage());
            assertEquals("08006", refused.getSQLState(),
                    "a stream that cannot be read any further is a connection failure");
            assertTrue(refused.getMessage() != null && !refused.getMessage().isBlank(),
                    "the refusal has to say what happened");
        }
    }

    /** And the connection must not pretend it is still usable afterwards. */
    @Test
    void theConnectionIsNotHandedOnAfterwards() throws Exception {
        PgSession session = PgSession.resume(HostileTransport.of(answer()),
                parameters(), 1, 2);
        Connection connection = PgConnection.resume(session, false);
        try (Statement statement = connection.createStatement()) {
            org.junit.jupiter.api.Assertions.assertThrows(SQLException.class,
                    () -> statement.executeQuery("select n from t"));
        }
        assertTrue(connection.isClosed(),
                "the stream is at a position nobody can make sense of, so a pool must not "
                + "hand this connection to the next caller");
    }
}
