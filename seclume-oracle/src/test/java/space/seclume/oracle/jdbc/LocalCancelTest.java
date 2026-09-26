package space.seclume.oracle.jdbc;

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
 * <p>Oracle needs no second connection but it does need the kernel's help. A
 * {@code !} goes down the same socket as <b>TCP urgent data</b> - delivered
 * ahead of everything queued, raising {@code SIGURG} on the far side - and an
 * ordinary break MARKER follows it in band. The marker on its own was tried
 * first and measured: the server is running the statement, not reading the
 * socket, so it sits in the receive buffer until the thing it was meant to
 * stop has finished.
 *
 * <p>What comes back is not an error but <b>more markers</b> - a break and a
 * reset - which the reading thread answers with a reset of its own, and only
 * then does {@code ORA-01013} arrive as an ordinary TTC error.
 *
 * <p>Three things are checked, and the third is the one that would be missed:
 * the query ends early, it ends as a cancellation rather than as a broken
 * connection, and <b>the connection still works afterwards</b>. A cancel that
 * leaves the session unusable has turned a timeout into a lost connection,
 * which in a pool under load is worse than the slow query was.
 */
@Timeout(120)
class LocalCancelTest {

    /** ORA-01013, "user requested cancel of current operation". */
    private static final String ORA_CANCELLED = "ORA-01013";

    private static final String HOST =
            System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);
    private static final String USER = "seclume_test";

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle listener on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:oracle://" + HOST + ":" + PORT + "/"
                + System.getProperty("seclume.oracle.service", "FREEPDB1")
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
                    // A cross join and not a sleep, and the choice is the
                    // finding. dbms_session.sleep(30) is not interruptible:
                    // the break arrives, the server takes it, and the sleep
                    // runs to its end anyway - which for an afternoon looked
                    // exactly like a cancellation that did not work. A CONNECT
                    // BY long enough to last thirty seconds runs out of memory
                    // first (ORA-30009). This runs until it is stopped and
                    // checks for a break while it does.
                    statement.execute("select count(*) from all_objects a, all_objects b "
                            + "where a.object_id + b.object_id > 0");
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
            assertNotNull(cancelled, "the query finished normally, so the sleep was never "
                    + "actually running and this test proved nothing");
            assertTrue(cancelled.getMessage().contains(ORA_CANCELLED),
                    "a cancellation has to arrive as " + ORA_CANCELLED + ", not as "
                    + cancelled.getSQLState() + ": " + cancelled.getMessage()
                    + " - an application retries a cancelled statement and gives up on a "
                    + "broken connection, and it tells them apart by this");

            // And the part a cancellation is easy to get wrong: what is left
            // on the wire. The backend sent an ErrorResponse and a
            // ReadyForQuery, and a driver that read only the first is now one
            // message behind for the rest of this connection's life.
            try (Statement afterwards = connection.createStatement();
                 ResultSet rows = afterwards.executeQuery("select 42 from dual")) {
                assertTrue(rows.next(), "the connection answered no rows after a cancellation");
                assertTrue(rows.getInt(1) == 42, "the connection is a message behind: it "
                        + "answered " + rows.getInt(1) + " to 'select 42'");
            }
        }
    }

    /**
     * A PL/SQL block in {@code dbms_session.sleep} is cancelled at its end,
     * not in the middle - and still cancelled.
     *
     * <p>The server takes the break and finishes the sleep before it acts on
     * it. Oracle's own thin driver, python-oracledb 4.0.2, does exactly the
     * same against the same server: {@code connection.cancel()} one second
     * into an eight-second sleep, ORA-01013 after eight. So this is the
     * server's behaviour, not a break this driver sends wrongly - and what a
     * driver owes is that the statement still ends as a cancellation, not as
     * a success, and that the connection is in step afterwards.
     */
    @Test
    void aPlsqlSleepEndsAsACancellationOnceItIsOver() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            Thread canceller = new Thread(() -> {
                try {
                    Thread.sleep(1000);
                    statement.cancel();
                } catch (Exception ignored) {
                    // the assertion below says what happened
                }
            }, "the-canceller");
            canceller.start();
            long before = System.nanoTime();
            SQLException cancelled = null;
            try {
                statement.execute("begin dbms_session.sleep(4); end;");
            } catch (SQLException e) {
                cancelled = e;
            }
            long millis = (System.nanoTime() - before) / 1_000_000L;
            canceller.join();
            assertNotNull(cancelled, "the sleep finished as a success after " + millis
                    + " ms although it was cancelled");
            assertTrue(cancelled.getMessage().contains(ORA_CANCELLED), cancelled.getMessage());
            try (ResultSet rows = statement.executeQuery("select 43 from dual")) {
                assertTrue(rows.next());
                assertTrue(rows.getInt(1) == 43, "the connection is out of step: it answered "
                        + rows.getInt(1));
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
            try (ResultSet rows = statement.executeQuery("select 1 from dual")) {
                assertTrue(rows.next());
            }
            statement.cancel();
            statement.cancel();
            try (ResultSet rows = statement.executeQuery("select 7 from dual")) {
                assertTrue(rows.next(), "the connection answered no rows after two "
                        + "cancellations of nothing");
                assertTrue(rows.getInt(1) == 7, "the connection answered " + rows.getInt(1));
            }
        }
    }
}
