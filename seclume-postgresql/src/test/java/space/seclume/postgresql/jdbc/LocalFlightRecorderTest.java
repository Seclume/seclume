package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.Flight;
import space.seclume.tck.TestHosts;

/**
 * The order of the conversation, which is the only thing that shows a
 * desynchronised stream.
 *
 * <p>Several of the defects fixed in this driver had the same shape: a
 * connection one message behind, working perfectly and answering the wrong
 * thing, with the failure arriving three calls later in code that did nothing.
 * Nothing that looks at one statement can see that. A list of what went out
 * and what came back, in sequence, shows it at a glance.
 *
 * <p>Two things are checked, and the second is the one that keeps the feature
 * honest: that the recording says what happened, and that it says
 * <b>nothing else</b> - no payload, no literal, no value. A diagnostic in this
 * library that carried content would be the same defect as the twenty-seven
 * exception messages that used to carry the SQL text.
 */
@Timeout(120)
class LocalFlightRecorderTest {

    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";
    /** Unmistakable, so its absence from the recording means something. */
    private static final String LITERAL = "zl-flight-literal-7b31d9";

    private static String url;
    private String previous;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no " + TestHosts.postgresPasswordFile());
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    TestHosts.postgres(), TestHosts.postgresPort()), 2000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + TestHosts.postgres()
                    + ":" + TestHosts.postgresPort());
        }
        url = "jdbc:seclume:postgresql://" + TestHosts.postgres()
                + ":" + TestHosts.postgresPort() + "/" + DATABASE
                + "?user=" + USER + "&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    @BeforeEach
    void switchItOn() {
        previous = System.getProperty("seclume.flight");
        System.setProperty("seclume.flight", "64");
    }

    @AfterEach
    void putItBack() {
        if (previous == null) {
            System.clearProperty("seclume.flight");
        } else {
            System.setProperty("seclume.flight", previous);
        }
    }

    @Test
    void theConversationIsRecordedInOrder() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            try (ResultSet rows = statement.executeQuery("select '" + LITERAL + "'")) {
                assertTrue(rows.next());
            }

            List<Flight.Message> recorded = Flight.of(connection).recent();
            assertTrue(!recorded.isEmpty(), "nothing was recorded although it was switched on");
            assertTrue(Flight.of(connection).messages() >= recorded.size());

            String shown = recorded.toString();
            // The shape of a simple query: the request out, then the
            // description, the row, the completion and the ready.
            assertTrue(shown.contains("-> ") && shown.contains("<- "),
                    "only one direction was recorded: " + shown);
            assertTrue(shown.contains("Query"), "the query itself is missing: " + shown);
            assertTrue(shown.contains("RowDescription"), "no description: " + shown);
            assertTrue(shown.contains("ReadyForQuery"), "no ready: " + shown);

            // The last of each, not the first: the login has a ReadyForQuery
            // of its own, and the first version of this assertion found it and
            // called the order wrong. The recording was right.
            int description = lastIndexOf(recorded, "RowDescription");
            int ready = lastIndexOf(recorded, "ReadyForQuery");
            assertTrue(description >= 0 && ready > description,
                    "the order is wrong, which is the one thing this records: " + shown);
        }
    }

    /**
     * The rule the whole feature stands or falls on.
     *
     * <p>Types and byte counts. Never a payload - not the statement, not a
     * literal, not a value, not a password during the handshake. A recorder
     * that kept the bytes would put every one of those in a ring buffer in the
     * heap, available to whatever reads a diagnostic.
     */
    @Test
    void theRecordingCarriesNoContent() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            try (ResultSet rows = statement.executeQuery(
                    "select '" + LITERAL + "' as " + '"' + LITERAL + '"')) {
                assertTrue(rows.next());
                assertEquals(LITERAL, rows.getString(1));
            }
            String shown = Flight.of(connection).recent().toString();
            assertTrue(!shown.contains(LITERAL),
                    "the recording carries the value that was in the answer: " + shown);
            assertTrue(!shown.contains("select"),
                    "the recording carries the statement text: " + shown);
        }
    }

    /** Off by default, and off costs nothing to ask about. */
    @Test
    void itIsOffUnlessAskedFor() throws Exception {
        System.clearProperty("seclume.flight");
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select 1")) {
            assertTrue(rows.next());
            assertTrue(Flight.of(connection).recent().isEmpty(),
                    "something was recorded although nobody asked");
            assertEquals(0, Flight.of(connection).messages());
        }
    }

    /**
     * A broken connection says what it last saw, in the exception that reports
     * it - the one place somebody is certain to look.
     */
    @Test
    void aBrokenConnectionCarriesTheTail() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            try (ResultSet rows = statement.executeQuery("select 1")) {
                assertTrue(rows.next());
            }
            // Killed from the server's side, so the next statement finds a
            // socket that is gone rather than a protocol error.
            try (Connection other = DriverManager.getConnection(url);
                 Statement killer = other.createStatement()) {
                killer.execute("select pg_terminate_backend("
                        + space.seclume.RoundTrips.of(connection) * 0
                        + backendPid(connection) + ")");
            }
            SQLException broken = assertThrows(SQLException.class,
                    () -> statement.executeQuery("select 2"));
            assertTrue(broken.getMessage().contains("the last "),
                    "the failure does not carry the recording: " + broken.getMessage());
            assertTrue(broken.getMessage().contains("ReadyForQuery"),
                    "the recording in the failure is empty: " + broken.getMessage());
        }
    }

    private static int backendPid(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select pg_backend_pid()")) {
            rows.next();
            return rows.getInt(1);
        }
    }

    private static int lastIndexOf(List<Flight.Message> recorded, String type) {
        for (int i = recorded.size() - 1; i >= 0; i--) {
            if (recorded.get(i).type().contains(type)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * The length of the message that carries the credential is not recorded.
     *
     * <p>Found by reading this recorder's own first output, where the
     * PasswordMessage stood with a byte count beside it. Under SCRAM that
     * count is decided by the protocol; under cleartext authentication it is
     * the password's length plus a constant, which is the single most useful
     * fact for anybody about to guess one.
     */
    @Test
    void theCredentialMessageHasNoLength() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            List<Flight.Message> recorded = Flight.of(connection).recent();
            boolean sawOne = false;
            for (Flight.Message message : recorded) {
                if (message.type().contains("Password")) {
                    sawOne = true;
                    assertEquals(Flight.WITHHELD, message.bytes(),
                            "the length of the credential message was recorded: " + message);
                }
            }
            assertTrue(sawOne, "no credential message was recorded at all, so this proves "
                    + "nothing: " + recorded);
        }
    }

}
