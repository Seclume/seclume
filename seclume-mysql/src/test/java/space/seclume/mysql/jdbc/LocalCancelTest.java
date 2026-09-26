package space.seclume.mysql.jdbc;

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
 * <p>MySQL has no out-of-band message for it. What it has is a statement -
 * {@code KILL QUERY <id>} - and a statement needs a connection, which cannot
 * be this one: it is blocked waiting for the answer being cancelled. So the
 * driver opens a second connection, logs in, runs one statement and closes it
 * again. A cancellation therefore costs a full handshake here, where
 * PostgreSQL costs sixteen bytes.
 *
 * <p>The outcome appears on the <b>original</b> connection, as MySQL error
 * 1317 with SQLState {@code 70100}.
 *
 * <p>Three things are checked, and the third is the one that would be missed:
 * the query ends early, it ends as a cancellation rather than as a broken
 * connection, and <b>the connection still works afterwards</b>. A cancel that
 * leaves the session unusable has turned a timeout into a lost connection,
 * which in a pool under load is worse than the slow query was.
 */
@Timeout(120)
class LocalCancelTest {

    /** MySQL's own code for "the statement was interrupted". */
    private static final String QUERY_CANCELED = "70100";

    private static final String HOST = System.getProperty("seclume.mysql.host",
            space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mysql.port", 3307);
    private static final String USER = "seclume_test";

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mysql-password"),
                Path.of("..", ".local-mysql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mysql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no MySQL on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:mysql://" + HOST + ":" + PORT + "/seclume_test"
                + "?user=" + USER + "&allowPublicKeyRetrieval=true&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    /**
     * A sleeping query is stopped, and MySQL says so in its own way.
     *
     * <p><b>Not by failing.</b> A killed {@code SLEEP()} does not raise
     * MySQL error 1317 - it returns early with the value <b>1</b> instead of
     * the 0 it returns when it slept the whole time. So the proof that the
     * cancellation landed is the row, not an exception: the query comes back
     * in under a second having been asked for thirty, and the value in it is
     * 1.
     *
     * <p>That is worth knowing rather than working around. An application
     * that cancels a statement on MySQL cannot assume it will see a failure -
     * some statements end with an error, some end with a result - and code
     * written against PostgreSQL's behaviour, where a cancelled query always
     * fails with 57014, is code that will silently accept a partial answer
     * here.
     */
    @Test
    void aSleepingQueryIsStoppedAndTheConnectionSurvives() throws Exception {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {

            CountDownLatch started = new CountDownLatch(1);
            AtomicReference<Integer> slept = new AtomicReference<>();
            AtomicReference<SQLException> outcome = new AtomicReference<>();
            AtomicReference<Throwable> wrong = new AtomicReference<>();

            Thread query = new Thread(() -> {
                try {
                    started.countDown();
                    try (ResultSet rows = statement.executeQuery("select sleep(30)")) {
                        if (rows.next()) {
                            slept.set(rows.getInt(1));
                        }
                    }
                } catch (SQLException failed) {
                    outcome.set(failed);
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

            SQLException failed = outcome.get();
            if (failed != null) {
                // The other shape MySQL uses. Accepted, and checked for being
                // the right one rather than for being any failure at all.
                assertTrue(QUERY_CANCELED.equals(failed.getSQLState()),
                        "the query failed, but not as a cancellation: "
                        + failed.getSQLState() + ": " + failed.getMessage());
            } else {
                assertNotNull(slept.get(), "the query returned no row at all");
                assertTrue(slept.get() == 1, "sleep() returned " + slept.get()
                        + ", which is what it returns when it slept the full thirty seconds - "
                        + "so nothing was cancelled and this test proved nothing");
            }

            // And the part a cancellation is easy to get wrong: what is left
            // on the wire. A driver that stopped reading in the middle of the
            // answer it was given is one packet behind for the rest of this
            // connection's life.
            try (Statement afterwards = connection.createStatement();
                 ResultSet rows = afterwards.executeQuery("select 42")) {
                assertTrue(rows.next(), "the connection answered no rows after a cancellation");
                assertTrue(rows.getInt(1) == 42, "the connection is a packet behind: it "
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
