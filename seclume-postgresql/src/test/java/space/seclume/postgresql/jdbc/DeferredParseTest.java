package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.tck.TestHosts;

/**
 * The Parse a prepared statement owes, and when it is paid.
 *
 * <p>A prepared statement's Parse rides with its first execution. Three
 * things went wrong with that, all found by Liquibase and all ending in
 * "prepared statement seclume_N does not exist":
 * <ul>
 *   <li>one slot for the owed Parse, so a second prepareStatement before the
 *       first ran replaced the first one's;</li>
 *   <li>a Parse counted as done once sent - when it failed, because a table
 *       did not exist yet, it was never sent again;</li>
 *   <li>a rollback discarded owed Parses along with the transaction's queue,
 *       though a prepared statement is not part of a transaction.</li>
 * </ul>
 */
class DeferredParseTest {

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

    @Test
    void twoStatementsPreparedBeforeEitherRuns() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             PreparedStatement one = connection.prepareStatement("select 1 + ?");
             PreparedStatement two = connection.prepareStatement("select 2 + ?")) {
            one.setInt(1, 10);
            two.setInt(1, 20);
            assertEquals(11, single(one));
            assertEquals(22, single(two));
            assertEquals(11, single(one));
        }
    }

    @Test
    void aParseThatFailedIsSentAgain() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement plain = connection.createStatement()) {
            plain.execute("drop table if exists zl_parse_later");
            try (PreparedStatement count =
                         connection.prepareStatement("select count(*) from zl_parse_later")) {
                assertThrows(SQLException.class, count::executeQuery,
                        "the table does not exist yet");
                plain.execute("create table zl_parse_later (x int)");
                assertEquals(0, single(count), "the statement has to work once the table does");
                assertEquals(0, single(count), "and again, without parsing twice");
            } finally {
                plain.execute("drop table if exists zl_parse_later");
            }
        }
    }

    @Test
    void aFailedParseInsideATransactionWithSettingsRidingAlong() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement plain = connection.createStatement()) {
            plain.execute("drop table if exists zl_parse_tx");
            connection.setAutoCommit(false);
            // A deferred setting rides in front of the next statement, with a
            // ReadyForQuery of its own ahead of the Parse's.
            connection.setReadOnly(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
            try (PreparedStatement count =
                         connection.prepareStatement("select count(*) from zl_parse_tx")) {
                assertThrows(SQLException.class, count::executeQuery);
                connection.rollback();
                connection.setAutoCommit(true);
                plain.execute("create table zl_parse_tx (x int)");
                assertEquals(0, single(count));
            } finally {
                connection.setAutoCommit(true);
                plain.execute("drop table if exists zl_parse_tx");
            }
        }
    }

    private static int single(PreparedStatement statement) throws SQLException {
        try (ResultSet rows = statement.executeQuery()) {
            rows.next();
            return rows.getInt(1);
        }
    }
}
