package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.internal.jdbc.ConnectionFacts;
import space.seclume.postgresql.PgSession;
import space.seclume.tck.TestHosts;

/**
 * The seam a JDBC connection is taken apart at: {@code detach()} under it,
 * {@link PgConnection#facts()} beside it, {@link PgConnection#resume} on the
 * other side. What is built on the seam is not this library's; that the seam
 * holds is.
 */
class DetachSeamTest {

    private static String url;

    @BeforeAll
    static void server() {
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no PostgreSQL password file");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no PostgreSQL on " + host + ":" + port);
        }
        url = "jdbc:seclume:postgresql://" + host + ":" + port + "/seclume_test"
                + "?user=seclume_test&tls=off&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/');
    }

    /** The connection whose session was handed over says it is closed, in JDBC's words. */
    @Test
    void aConnectionWhoseSessionWasHandedOverIsClosed() throws Exception {
        Connection connection = DriverManager.getConnection(url);
        PgSession.Detached detached = connection.unwrap(PgSession.class).detach();
        try {
            assertTrue(connection.isClosed());
            SQLException refused = assertThrows(SQLException.class,
                    connection::createStatement);
            assertEquals("08003", refused.getSQLState());
        } finally {
            detached.stream().close();
        }
    }

    /**
     * {@code setAutoCommit(false)} and nothing after it: the BEGIN waits for
     * the next statement. {@code detach()} sends it rather than leaving it
     * behind - the server already has the transaction open when the stream is
     * handed over, and says so to anybody who asks.
     */
    @Test
    void aWaitingBeginReachesTheServerBeforeTheHandOver() throws Exception {
        Connection connection = DriverManager.getConnection(url);
        String backend = ask(connection, "select pg_backend_pid()");
        connection.setAutoCommit(false);
        PgSession.Detached detached = connection.unwrap(PgSession.class).detach();
        try (Connection other = DriverManager.getConnection(url)) {
            assertEquals("idle in transaction", ask(other,
                    "select state from pg_stat_activity where pid = " + backend),
                    "the BEGIN was left behind in the object that gave the session up");
        } finally {
            detached.stream().close();
        }
    }

    /** What the connection knew about itself goes into facts() and back out of resume(). */
    @Test
    void factsCarryWhatTheConnectionKnew() throws Exception {
        Connection connection = DriverManager.getConnection(url);
        connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
        connection.setReadOnly(true);
        connection.setAutoCommit(false);
        connection.prepareStatement("select 1").close();
        ConnectionFacts facts = connection.unwrap(PgConnection.class).facts();
        assertFalse(facts.autoCommit());
        assertTrue(facts.readOnly());
        assertEquals(Connection.TRANSACTION_REPEATABLE_READ, facts.isolation());
        assertTrue(facts.statements() > 0, "the statement counter was not counted");

        PgSession.Detached detached = connection.unwrap(PgSession.class).detach();
        try (Connection resumed = PgConnection.resume(PgSession.resume(detached.stream(),
                detached.parameters(), detached.backendProcessId(),
                detached.backendSecretKey()), facts)) {
            assertFalse(resumed.getAutoCommit());
            assertTrue(resumed.isReadOnly());
            assertEquals(Connection.TRANSACTION_REPEATABLE_READ,
                    resumed.getTransactionIsolation());
            assertEquals(facts, resumed.unwrap(PgConnection.class).facts());
            resumed.rollback();
        }
    }

    private static String ask(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }
}
