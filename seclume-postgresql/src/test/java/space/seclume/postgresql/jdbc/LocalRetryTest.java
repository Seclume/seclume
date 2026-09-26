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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.Retry;
import space.seclume.tck.TestHosts;

/**
 * A serialization failure, made on purpose, and survived on purpose.
 *
 * <p>{@link Retry}'s classification is checked without a server - it is a
 * decision about exceptions. This is the other half: that a real database
 * really does produce the failure the classification is written for, that the
 * driver really does report it with the SQLState the classification reads, and
 * that the block really does run again and succeed.
 *
 * <p><b>The negative control is the part that makes this worth having.</b> The
 * same two transactions are run first <b>without</b> the retry, and one of
 * them has to fail with {@code 40001}. Without that, a test where both
 * transactions happen to succeed proves nothing at all - and two transactions
 * only conflict if they really are concurrent, which is arranged here with
 * latches rather than hoped for.
 */
@Timeout(180)
class LocalRetryTest {

    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";
    /** PostgreSQL's code for "this transaction cannot stand beside that one". */
    private static final String SERIALIZATION_FAILURE = "40001";

    private static String url;

    @BeforeAll
    static void findTheServer() throws Exception {
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

        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists zl_retry");
            statement.execute("create table zl_retry (id int primary key, n int not null)");
            statement.execute("insert into zl_retry values (1, 0), (2, 0)");
        }
    }

    @AfterAll
    static void tidyUp() throws Exception {
        if (url == null) {
            return;
        }
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists zl_retry");
        }
    }

    private static void reset() throws SQLException {
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            statement.execute("update zl_retry set n = 0");
        }
    }

    /**
     * Each transaction reads the other's row and writes its own.
     *
     * <p>Under {@code serializable} that is the textbook write skew, and
     * PostgreSQL's predicate locks catch it: one of the two commits and the
     * other is told 40001. Which of the two loses is not decided here and does
     * not need to be.
     */
    private static void crossOver(Connection connection, int mine, int theirs,
                                  java.util.concurrent.CyclicBarrier betweenReadAndWrite)
            throws SQLException {
        try (PreparedStatement read = connection.prepareStatement(
                "select n from zl_retry where id = ?")) {
            read.setInt(1, theirs);
            try (ResultSet rows = read.executeQuery()) {
                assertTrue(rows.next());
                rows.getInt(1);
            }
        }
        // Both have read before either writes, which is what makes the
        // conflict certain rather than likely. On a retry the other party is
        // long gone, so waiting here times out and carries on - which is
        // correct: the second attempt is supposed to succeed.
        meet(betweenReadAndWrite);
        try (PreparedStatement write = connection.prepareStatement(
                "update zl_retry set n = n + 1 where id = ?")) {
            write.setInt(1, mine);
            write.executeUpdate();
        }
    }

    private static void meet(java.util.concurrent.CyclicBarrier barrier) {
        try {
            barrier.await(5, TimeUnit.SECONDS);
        } catch (Exception alone) {
            // The other side is not coming: it is retrying, or it has
            // finished. Either way this one carries on.
            Thread.interrupted();
        }
    }

    /**
     * The control: without a retry, one of the two has to lose.
     *
     * <p>If this ever stops failing, every assertion in the test below it
     * becomes meaningless - the two transactions would no longer be in
     * conflict and the retry would have nothing to do.
     */
    @Test
    void withoutARetryOneOfThemLoses() throws Exception {
        reset();
        AtomicReference<SQLException> lost = new AtomicReference<>();
        runBothAtOnce((connection, mine, theirs, barrier) -> {
            try {
                connection.setAutoCommit(false);
                connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
                crossOver(connection, mine, theirs, barrier);
                connection.commit();
            } catch (SQLException conflict) {
                lost.compareAndSet(null, conflict);
                try {
                    connection.rollback();
                } catch (SQLException ignored) {
                    // The failure above is the one being reported.
                }
            }
        });

        SQLException failure = lost.get();
        assertTrue(failure != null, "neither transaction failed, so they were not in "
                + "conflict and this test proves nothing about the retry below");
        assertEquals(SERIALIZATION_FAILURE, failure.getSQLState(),
                "a write skew has to arrive as " + SERIALIZATION_FAILURE + ", not as "
                + failure.getSQLState() + ": " + failure.getMessage()
                + " - Retry.worthRetrying reads exactly this");
        assertTrue(Retry.worthRetrying(failure),
                "the classification does not recognise the failure a real server produced");
    }

    /** And with one, both get through - the second by running again. */
    @Test
    void withARetryBothGetThrough() throws Exception {
        reset();
        AtomicInteger runs = new AtomicInteger();
        AtomicReference<SQLException> failed = new AtomicReference<>();

        runBothAtOnce((connection, mine, theirs, barrier) -> {
            try {
                connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
                Retry.inTransaction(connection, transaction -> {
                    runs.incrementAndGet();
                    crossOver(transaction, mine, theirs, barrier);
                });
            } catch (SQLException stillFailed) {
                failed.compareAndSet(null, stillFailed);
            }
        });

        assertTrue(failed.get() == null, "a transaction failed even with the retry: "
                + (failed.get() == null ? "" : failed.get().getMessage()));
        assertTrue(runs.get() > 2, "the block ran " + runs.get() + " times for two "
                + "transactions, so nothing was ever retried and the conflict did not happen");

        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select sum(n) from zl_retry")) {
            assertTrue(rows.next());
            assertEquals(2, rows.getInt(1),
                    "both transactions had to land exactly once each");
        }
    }

    /** A failure that will happen again is not retried, however often it is offered. */
    @Test
    void whatWillFailAgainIsNotRunAgain() throws Exception {
        reset();
        AtomicInteger runs = new AtomicInteger();
        try (Connection connection = DriverManager.getConnection(url)) {
            SQLException thrown = assertThrows(SQLException.class, () ->
                    Retry.inTransaction(connection, transaction -> {
                        runs.incrementAndGet();
                        try (Statement statement = transaction.createStatement()) {
                            statement.execute("insert into zl_retry values (1, 0)");
                        }
                    }));
            assertTrue(thrown.getSQLState().startsWith("23"),
                    "a duplicate key is class 23, not " + thrown.getSQLState());
            assertEquals(1, runs.get(), "a unique-constraint violation was run "
                    + runs.get() + " times - it would have failed identically every time");
        }
    }

    // ---- two transactions, genuinely at the same time ----------------------

    @FunctionalInterface
    private interface Party {
        void run(Connection connection, int mine, int theirs,
                 java.util.concurrent.CyclicBarrier betweenReadAndWrite) throws SQLException;
    }

    /**
     * Two connections, released together, meeting between read and write.
     *
     * <p>Starting two threads and hoping is not enough: they would usually
     * miss each other entirely, both commit, and the test would pass by not
     * testing anything - the failure mode this whole class is written to
     * avoid.
     */
    private static void runBothAtOnce(Party party) throws Exception {
        java.util.concurrent.CyclicBarrier betweenReadAndWrite =
                new java.util.concurrent.CyclicBarrier(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch go = new CountDownLatch(1);
        AtomicReference<Throwable> broke = new AtomicReference<>();

        Thread[] parties = new Thread[2];
        for (int i = 0; i < 2; i++) {
            int mine = i + 1;
            int theirs = 2 - i;
            parties[i] = new Thread(() -> {
                try (Connection connection = DriverManager.getConnection(url)) {
                    ready.countDown();
                    go.await(30, TimeUnit.SECONDS);
                    party.run(connection, mine, theirs, betweenReadAndWrite);
                } catch (Throwable wrong) {
                    broke.compareAndSet(null, wrong);
                    ready.countDown();
                }
            }, "retry-party-" + mine);
            parties[i].setDaemon(true);
        }
        for (Thread thread : parties) {
            thread.start();
        }
        assertTrue(ready.await(30, TimeUnit.SECONDS), "a party never connected");
        go.countDown();
        for (Thread thread : parties) {
            thread.join(60_000);
            assertTrue(!thread.isAlive(), thread.getName() + " never finished");
        }
        assertTrue(broke.get() == null, "a party broke: " + broke.get());
    }
}
