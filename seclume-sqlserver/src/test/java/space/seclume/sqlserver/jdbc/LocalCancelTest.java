package space.seclume.sqlserver.jdbc;

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
 * <p>TDS needs no second connection: an ATTENTION is a bare eight-byte
 * header written down the same socket while the reader is still blocked
 * waiting for the answer it interrupts. A socket is full duplex, so the write
 * does not wait for the read.
 *
 * <p>And the server sends no error for it. It finishes the message it was in
 * the middle of - which may already carry rows - and sets the ATTENTION bit in
 * the closing DONE. That bit is the <b>only</b> evidence the cancellation
 * happened, which is why a driver that does not look at it reports a short
 * result as a complete one. This driver turns it into SQLState {@code HY008}.
 *
 * <p>Three things are checked, and the third is the one that would be missed:
 * the query ends early, it ends as a cancellation rather than as a broken
 * connection, and <b>the connection still works afterwards</b>. A cancel that
 * leaves the session unusable has turned a timeout into a lost connection,
 * which in a pool under load is worse than the slow query was.
 */
@Timeout(120)
class LocalCancelTest {

    /** The standard code for an operation that was cancelled. */
    private static final String QUERY_CANCELED = "HY008";

    private static final String HOST =
            System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);
    private static final String USER = "sa";

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mssql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:sqlserver://" + HOST + ":" + PORT + "/master"
                + "?user=" + USER + "&trustServerCertificate=true&provider=file&path="
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
                    // execute and not executeQuery: WAITFOR produces no rows,
                    // and the question here is whether it ends, not what it
                    // returns.
                    statement.execute("waitfor delay '00:00:30'");
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
