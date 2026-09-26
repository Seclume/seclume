package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * Cancellation, which is the one JDBC call that arrives from another thread.
 *
 * <p>The misuse contract asks whether {@code cancel()} is harmless when there
 * is nothing to cancel. This asks the question that matters: <b>does it stop
 * anything.</b> A driver can satisfy the first by doing nothing at all, and
 * then a query timeout is a promise nobody keeps - the statement runs to the
 * end, the pool's connection is held for as long as the database feels like
 * it, and the application's deadline was decoration.
 *
 * <p>PostgreSQL cancels out of band: the connection running the query is
 * blocked waiting for its answer, so the request goes down a second socket,
 * carrying the process id and secret key the server handed out at login. The
 * server signals the backend, the backend abandons the query, and the
 * <b>original</b> connection is where the outcome appears - as an error with
 * SQLState {@code 57014}.
 *
 * <p>Three things are checked, and the third is the one that would be missed:
 * the query ends early, it ends as a cancellation rather than as a broken
 * connection, and <b>the connection still works afterwards</b>. A cancel that
 * leaves the session unusable has turned a timeout into a lost connection,
 * which in a pool under load is worse than the slow query was.
 */
@Timeout(120)
class LocalCancelTest {

    /** PostgreSQL's own code for "cancelled because somebody asked". */
    private static final String QUERY_CANCELED = "57014";

    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";

    private static String url;

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

    @Test
    void aSleepingQueryIsStoppedAndTheConnectionSurvives() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {

            CountDownLatch started = new CountDownLatch(1);
            AtomicReference<SQLException> outcome = new AtomicReference<>();
            AtomicReference<Throwable> wrong = new AtomicReference<>();

            Thread query = new Thread(() -> {
                try {
                    started.countDown();
                    try (ResultSet rows = statement.executeQuery("select pg_sleep(30)")) {
                        rows.next();
                    }
                } catch (SQLException cancelled) {
                    outcome.set(cancelled);
                } catch (Throwable other) {
                    wrong.set(other);
                }
            }, "the-query-being-cancelled");
            query.setDaemon(true);

            long before = System.nanoTime();
            query.start();
            assertTrue(started.await(10, TimeUnit.SECONDS), "the query thread never started");
            // Long enough that the server is certainly executing it: a cancel
            // that arrives before the query does is discarded, and the test
            // would then wait out the full thirty seconds and say nothing
            // useful about why.
            Thread.sleep(500);

            statement.cancel();

            query.join(20_000);
            long seconds = (System.nanoTime() - before) / 1_000_000_000L;

            assertTrue(wrong.get() == null, "the query failed with something that is not a "
                    + "SQLException: " + wrong.get());
            assertTrue(!query.isAlive(), "the query was still running twenty seconds after "
                    + "the cancellation - nothing was stopped");
            assertTrue(seconds < 25, "the query ran for " + seconds + " seconds, so it ran to "
                    + "the end and the cancellation did nothing");

            SQLException cancelled = outcome.get();
            assertNotNull(cancelled, "the query finished normally, so pg_sleep(30) was never "
                    + "actually running and this test proved nothing");
            assertTrue(QUERY_CANCELED.equals(cancelled.getSQLState()),
                    "a cancellation has to arrive as " + QUERY_CANCELED + ", not as "
                    + cancelled.getSQLState() + ": " + cancelled.getMessage()
                    + " - an application retries a cancelled statement and gives up on a "
                    + "broken connection, and it tells them apart by this code");

            // And the part a cancellation is easy to get wrong: what is left
            // on the wire. The backend sent an ErrorResponse and a
            // ReadyForQuery, and a driver that read only the first is now one
            // message behind for the rest of this connection's life.
            try (Statement afterwards = connection.createStatement();
                 ResultSet rows = afterwards.executeQuery("select 42")) {
                assertTrue(rows.next(), "the connection answered no rows after a cancellation");
                assertTrue(rows.getInt(1) == 42, "the connection is a message behind: it "
                        + "answered " + rows.getInt(1) + " to 'select 42'");
            }
        }
    }

    /**
     * The other half: a cancel nobody needed must not break anything.
     *
     * <p>This is what a query-timeout thread does every time the query
     * finishes first, which is nearly always.
     */
    @Test
    void cancellingWhenNothingIsRunningCostsNothing() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            try (ResultSet rows = statement.executeQuery("select 1")) {
                assertTrue(rows.next());
            }
            statement.cancel();
            statement.cancel();
            try (ResultSet rows = statement.executeQuery("select 7")) {
                assertTrue(rows.next(), "the connection answered no rows after two "
                        + "cancellations of nothing");
                assertTrue(rows.getInt(1) == 7, "the connection answered " + rows.getInt(1));
            }
        }
    }
}
