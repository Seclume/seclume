package space.seclume.oracle.jdbc;

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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLTimeoutException;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;


/**
 * {@code setQueryTimeout}, which until cancellation existed was a refusal.
 *
 * <p>The driver used to throw {@code SQLFeatureNotSupportedException} for any
 * non-zero timeout, on the grounds that accepting one it could not enforce
 * would be a lie. It can enforce one now, and this is the difference between
 * the two claims: <b>the statement has to actually stop</b>, in about the time
 * that was asked for rather than in its own time.
 *
 * <p>And it has to stop as a {@link SQLTimeoutException}. The four protocols
 * report a cancelled statement in four different ways - and MySQL sometimes
 * does not report it at all - so a caller handed only the vendor's code would
 * have to know which database it is talking to in order to know its deadline
 * expired. A retry is written against the JDBC type, not against 57014.
 */
@Timeout(180)
class LocalQueryTimeoutTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);
    private static final String USER = "seclume_test";

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-oracle-password"), Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:oracle://" + HOST + ":" + PORT + "/"
                + System.getProperty("seclume.oracle.service", "FREEPDB1")
                + "?user=" + USER + "&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    @Test
    void aStatementThatOverrunsItsDeadlineIsStopped() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.setQueryTimeout(1);
            assertEquals(1, statement.getQueryTimeout(), "the timeout was not kept");

            long before = System.nanoTime();
            SQLException thrown = assertThrows(SQLException.class,
                    () -> statement.execute("select count(*) from all_objects a, all_objects b where a.object_id + b.object_id > 0"),
                    "a statement given one second was not stopped");
            long millis = (System.nanoTime() - before) / 1_000_000L;

            assertTrue(thrown instanceof SQLTimeoutException,
                    "a deadline that expired has to arrive as SQLTimeoutException, not as "
                    + thrown.getClass().getSimpleName() + ": " + thrown.getMessage()
                    + " - an application's retry is written against the JDBC type");
            assertTrue(millis < 10_000, "the statement took " + millis + " ms for a timeout "
                    + "of one second, so the deadline did not stop it");

            // The connection has to survive its own timeout. A driver that
            // read the error and not the ReadyForQuery behind it is one
            // message behind for the rest of this connection's life - and in
            // a pool it goes straight back to the next caller.
            try (ResultSet rows = statement.executeQuery("select 42 from dual")) {
                assertTrue(rows.next());
                assertEquals(42, rows.getInt(1), "the connection is a message behind");
            }
        }
    }

    /**
     * The case that happens millions of times for every one above.
     *
     * <p>A timeout is set, the statement finishes well inside it, and nothing
     * must happen: no cancellation on the wire, no exception, and the timer
     * gone. A driver that leaves the timer armed cancels the <b>next</b>
     * statement on that connection a second later.
     */
    @Test
    void aStatementThatFinishesInTimeIsLeftAlone() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.setQueryTimeout(30);
            for (int i = 0; i < 5; i++) {
                try (ResultSet rows = statement.executeQuery("select " + i + " from dual")) {
                    assertTrue(rows.next());
                    assertEquals(i, rows.getInt(1));
                }
            }
            // And a second later, when a leaked timer would have fired.
            Thread.sleep(1_200);
            try (ResultSet rows = statement.executeQuery("select 99 from dual")) {
                assertTrue(rows.next());
                assertEquals(99, rows.getInt(1),
                        "a timer from an earlier statement reached this one");
            }
        }
    }

    /** Zero is no limit, and a negative number is still an error. */
    @Test
    void theBoundsAreStillTheBounds() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.setQueryTimeout(0);
            assertEquals(0, statement.getQueryTimeout());
            assertThrows(SQLException.class, () -> statement.setQueryTimeout(-1),
                    "a negative timeout has to be refused");
        }
    }
}
