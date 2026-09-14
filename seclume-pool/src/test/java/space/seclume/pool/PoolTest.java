package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLNonTransientConnectionException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * The mechanics of the pool.
 *
 * <p>Everything here runs without a database. What is checked is exactly what a
 * pool can get wrong: opening more connections than allowed, handing out a
 * broken one, passing on state, losing a connection while
 * Zurueckgeben verlieren.
 */
class PoolTest {

    private static PoolSettings settings(int max) {
        PoolSettings settings = new PoolSettings();
        settings.setName("test");
        settings.setMaximumPoolSize(max);
        settings.setConnectionTimeout(Duration.ofMillis(500));
        settings.setValidationTimeout(Duration.ofSeconds(1));
        return settings;
    }

    /**
     * The timeout says who is holding the connections.
     *
     * <p>"request timed out after 30000ms" is true and useless: the question
     * at that moment is always the same, and the pool is the only one who
     * knows the answer. With leak detection on, the stack trace of the borrow
     * is in the message - and with it off, the message says which setting to
     * change before the next incident.
     */
    @Test
    void aTimeoutNamesTheStateAndTheOldestHolders() throws Exception {
        PoolSettings settings = new PoolSettings();
        settings.setName("busy-pool");
        settings.setMaximumPoolSize(1);
        settings.setConnectionTimeout(Duration.ofMillis(150));
        settings.setLeakDetectionThreshold(Duration.ofSeconds(30));
        try (SeclumePool pool = new SeclumePool(new StubDataSource(), settings);
             Connection held = pool.getConnection()) {
            assertNotNull(held);
            SQLException thrown = assertThrows(SQLException.class, pool::getConnection);
            String message = thrown.getMessage();
            assertTrue(message.contains("busy-pool"), message);
            assertTrue(message.contains("1 of 1 in use"), message);
            assertTrue(message.contains("out for"), message);
            assertTrue(message.contains("aTimeoutNamesTheStateAndTheOldestHolders"),
                    "the stack trace of the borrow belongs in the message: " + message);
        }
    }

    /** And without leak detection it says which setting would have helped. */
    @Test
    void aTimeoutWithoutLeakDetectionSaysWhichSettingIsMissing() throws Exception {
        PoolSettings settings = new PoolSettings();
        settings.setName("quiet-pool");
        settings.setMaximumPoolSize(1);
        settings.setConnectionTimeout(Duration.ofMillis(150));
        try (SeclumePool pool = new SeclumePool(new StubDataSource(), settings);
             Connection held = pool.getConnection()) {
            assertNotNull(held);
            SQLException thrown = assertThrows(SQLException.class, pool::getConnection);
            assertTrue(thrown.getMessage().contains("leak-detection-threshold"),
                    thrown.getMessage());
        }
    }

    @Test
    void reusesTheSameConnection() throws Exception {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings(4))) {
            Connection first;
            try (Connection connection = pool.getConnection()) {
                first = ((PooledConnection) connection).delegate();
                assertEquals(1, source.openedCount());
                assertEquals(1, pool.activeCount());
            }
            assertEquals(0, pool.activeCount());
            assertEquals(1, pool.idleCount());

            try (Connection connection = pool.getConnection()) {
                // The same real connection, only wrapped anew.
                assertSame(first, ((PooledConnection) connection).delegate());
                assertEquals(1, source.openedCount(), "the pool opened a second connection");
            }
        }
    }

    @Test
    void neverExceedsTheMaximum() throws Exception {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings(3))) {
            List<Connection> held = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                held.add(pool.getConnection());
            }
            assertEquals(3, pool.activeCount());
            assertEquals(3, source.openedCount());

            // The fourth has to wait and then give up.
            SQLException failure = assertThrows(SQLException.class, pool::getConnection);
            assertTrue(failure.getMessage().contains("no connection available"),
                    failure.getMessage());
            assertEquals(3, source.openedCount(), "the pool opened one too many");
            assertEquals(1, pool.statistics().timeouts());

            for (Connection connection : held) {
                connection.close();
            }
            assertEquals(0, pool.activeCount());
        }
    }

    /** If a thread waits, it gets the connection as soon as someone returns one. */
    @Test
    void aWaiterGetsTheNextFreeConnection() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings(1);
        settings.setConnectionTimeout(Duration.ofSeconds(5));
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            Connection held = pool.getConnection();
            CountDownLatch waiting = new CountDownLatch(1);
            CountDownLatch got = new CountDownLatch(1);
            AtomicInteger failures = new AtomicInteger();

            Thread waiter = Thread.ofVirtual().start(() -> {
                waiting.countDown();
                try (Connection connection = pool.getConnection()) {
                    assertFalse(connection.isClosed());
                    got.countDown();
                } catch (SQLException e) {
                    failures.incrementAndGet();
                }
            });

            assertTrue(waiting.await(2, TimeUnit.SECONDS));
            held.close();
            assertTrue(got.await(5, TimeUnit.SECONDS), "the waiter never got a connection");
            waiter.join();
            assertEquals(0, failures.get());
            assertEquals(1, source.openedCount(), "the pool opened a second connection");
        }
    }

    /**
     * The report says who holds what - the answer to "why is the pool empty".
     */
    @Test
    void reportsWhoHoldsWhat() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings(2);
        settings.setLeakDetectionThreshold(Duration.ofMinutes(1));
        try (SeclumePool pool = new SeclumePool(source, settings);
             Connection held = pool.getConnection()) {
            assertFalse(held.isClosed());
            String report = pool.report();
            assertTrue(report.contains("1 out"), report);
            assertTrue(report.contains("IN_USE"), report);
            assertTrue(report.contains("reportsWhoHoldsWhat"),
                    "the stack of the borrow is missing: " + report);
        }
    }

    /**
     * A rotated secret retires the connections that stand - without an outage.
     *
     * <p>Every other pool has to keep the password in order to reconnect;
     * this one asks the source anew for every connection, so a rotation is
     * not a special case but the normal path, triggered on purpose.
     */
    @Test
    void rotatingTheSecretRetiresTheOldConnections() throws Exception {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings(4))) {
            Connection first = pool.getConnection();
            Connection second = pool.getConnection();
            Connection firstReal = ((PooledConnection) first).delegate();
            first.close();                        // one free, one still out

            assertEquals(1, pool.rotateSecret(true), "the free one goes right away");
            assertTrue(firstReal.isClosed(), "the free connection was not closed");

            Connection secondReal = ((PooledConnection) second).delegate();
            second.close();                       // comes back after the rotation
            assertTrue(secondReal.isClosed(), "the borrowed one was not retired on return");

            try (Connection fresh = pool.getConnection()) {
                assertNotSame(firstReal, ((PooledConnection) fresh).delegate());
                assertNotSame(secondReal, ((PooledConnection) fresh).delegate());
            }
            assertEquals(1, pool.rotations());
        }
    }

    /**
     * The maximum holds even when housekeeping keeps stocking up.
     *
     * <p>The permit counts living connections, not borrowings. Whoever opens
     * one takes a permit and keeps it until the connection is retired - and a
     * refill that gave the permit back afterwards would let the pool grow past
     * its maximum, quietly and only under load.
     */
    @Test
    void neverOpensMoreThanTheMaximum() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings(3);
        settings.setMinimumIdle(3);
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            pool.warmup();
            List<Connection> held = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                held.add(pool.getConnection());
            }
            assertEquals(3, pool.totalCount());
            assertThrows(SQLException.class, pool::getConnection,
                    "a fourth connection was handed out");
            for (Connection connection : held) {
                connection.close();
            }
            assertEquals(3, source.openedCount(), "the pool opened more than three");
        }
    }

    /**
     * No connection may be in two hands at once.
     *
     * <p>The pool keeps no list of free connections - it reads the state of
     * every entry instead, which is what makes borrowing cheap. The price is
     * that an entry becomes visible the moment it enters the inventory, and a
     * freshly opened one must therefore <b>not</b> start as free: otherwise a
     * second thread claims it in the gap before the opener marks it as its
     * own. That is a bug you get once and then guard forever.
     */
    @Test
    void neverHandsTheSameConnectionToTwoCallers() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings(8);
        settings.setConnectionTimeout(Duration.ofSeconds(5));
        int threads = 16;
        int rounds = 200;
        java.util.Set<Connection> inUse = java.util.concurrent.ConcurrentHashMap.newKeySet();
        java.util.concurrent.atomic.AtomicInteger clashes =
                new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicInteger failures =
                new java.util.concurrent.atomic.AtomicInteger();

        try (SeclumePool pool = new SeclumePool(source, settings)) {
            CountDownLatch start = new CountDownLatch(1);
            List<Thread> workers = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                Thread worker = Thread.ofVirtual().unstarted(() -> {
                    try {
                        start.await();
                        for (int round = 0; round < rounds; round++) {
                            try (Connection connection = pool.getConnection()) {
                                Connection real = ((PooledConnection) connection).delegate();
                                if (!inUse.add(real)) {
                                    clashes.incrementAndGet();
                                }
                                Thread.yield();
                                inUse.remove(real);
                            }
                        }
                    } catch (Exception e) {
                        failures.incrementAndGet();
                    }
                });
                workers.add(worker);
                worker.start();
            }
            start.countDown();
            for (Thread worker : workers) {
                worker.join();
            }
            assertEquals(0, failures.get(), "a borrow failed");
            assertEquals(0, clashes.get(), "the same connection went out twice at once");
            assertTrue(source.openedCount() <= 8,
                    "the pool opened more than its maximum: " + source.openedCount());
        }
    }

    /**
     * A connection freshly back from the application is handed out again
     * <b>without</b> asking the server whether it is alive.
     *
     * <p>The probe is a full round trip, and it was the most expensive thing
     * in the whole pool: measured against HikariCP, borrowing went from a
     * fraction of a microsecond to sixty. Whoever wants the paranoid variant
     * sets the window to zero - the test below does exactly that.
     */
    @Test
    void doesNotProbeAConnectionThatJustCameBack() throws Exception {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings(2))) {
            for (int i = 0; i < 5; i++) {
                pool.getConnection().close();
            }
            assertEquals(0, source.handedOut().get(0).validations.get(),
                    "the pool asked the server on every handout");
        }
    }

    /**
     * A connection the server has closed must not go out - with the window at
     * zero, which is what makes the probe happen on every handout.
     */
    @Test
    void replacesAConnectionThatDiedWhileIdle() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings(2);
        settings.setValidationBypassWindow(Duration.ZERO);
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            Connection first;
            try (Connection connection = pool.getConnection()) {
                first = ((PooledConnection) connection).delegate();
            }
            // The server threw it away while it sat in the pool.
            source.handedOut().get(0).valid = false;

            try (Connection connection = pool.getConnection()) {
                assertNotSame(first, ((PooledConnection) connection).delegate());
            }
            assertEquals(2, source.openedCount());
            assertTrue(source.handedOut().get(0).closed.get(),
                    "the dead connection was not closed");
        }
    }

    /** What one application sets, the next must not inherit. */
    @Test
    void resetsTheConnectionStateOnReturn() throws Exception {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings(1))) {
            try (Connection connection = pool.getConnection()) {
                connection.setAutoCommit(false);
                connection.setReadOnly(true);
                connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            }
            StubDataSource.StubConnection state = source.handedOut().get(0);
            assertTrue(state.autoCommit, "autoCommit was not restored");
            assertFalse(state.readOnly, "readOnly was not restored");
            assertEquals(Connection.TRANSACTION_READ_COMMITTED, state.isolation);
            // An open transaction is rolled back, not committed.
            assertEquals(1, state.rollbacks.get(), "the open transaction was not rolled back");
        }
    }

    /** After a connection failure the connection does not go back into the pool. */
    @Test
    void aBrokenConnectionIsNotReturnedToThePool() throws Exception {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings(2))) {
            Connection connection = pool.getConnection();
            // The stub does not know nativeSQL - it throws without a SQLState,
            // which is what an ordinary SQL error looks like from here.
            assertThrows(SQLException.class, () -> connection.nativeSQL("select 1"));
            connection.close();
            assertEquals(1, pool.idleCount(),
                    "a plain SQL error must not throw the connection away");

            // An abort is something else: the connection is done for afterwards.
            Connection second = pool.getConnection();
            second.abort(Runnable::run);
            assertEquals(0, pool.idleCount(), "an aborted connection came back into the pool");
        }
    }

    @Test
    void closingTwiceIsHarmless() throws Exception {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings(2))) {
            Connection connection = pool.getConnection();
            connection.close();
            connection.close();
            assertEquals(1, pool.idleCount(), "the connection went back into the pool twice");
            assertTrue(connection.isClosed());
            assertThrows(SQLException.class, connection::createStatement);
        }
    }

    /**
     * {@code minimumIdle} means "this many stand ready" - not merely "this
     * many are not closed". Without refilling, the pool would be back at zero
     * after a quiet night, despite being configured.
     */
    @Test
    void refillsUpToMinimumIdle() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings(5);
        settings.setMinimumIdle(2);
        // The housekeeping thread runs at the beat of the validation timeout.
        settings.setValidationTimeout(Duration.ofMillis(250));
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            assertEquals(0, pool.idleCount(), "the pool opened connections without being asked");

            long deadline = System.currentTimeMillis() + 5000;
            while (pool.idleCount() < 2 && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }
            assertEquals(2, pool.idleCount(), "the pool did not refill to minimumIdle");

            // And no more than that - stock keeping, not an end in itself.
            Thread.sleep(600);
            assertEquals(2, pool.idleCount(), "the pool kept opening connections");
        }
    }

    /**
     * The peak may grow to the maximum, after which the pool gives back again.
     *
     * <p>This is the normal case for an application with load peaks: a hundred
     * concurrent requests during the day, three at night. Without shrinking,
     * the pool keeps a hundred sessions open that the server manages, pays for
     * and counts in
     * its own connection limit.
     */
    @Test
    void growsToTheMaximumAndShrinksBackAgain() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings(8);
        settings.setMinimumIdle(2);
        settings.setIdleTimeout(Duration.ofMillis(300));
        settings.setValidationTimeout(Duration.ofMillis(250));
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            // Load spike: all eight at once.
            List<Connection> held = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                held.add(pool.getConnection());
            }
            assertEquals(8, pool.activeCount());
            assertEquals(8, source.openedCount());

            for (Connection connection : held) {
                connection.close();
            }
            assertEquals(8, pool.idleCount(), "the connections did not come back");

            // After that nothing happens any more - the pool has to give back.
            long deadline = System.currentTimeMillis() + 5000;
            while (pool.idleCount() > 2 && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }
            assertEquals(2, pool.idleCount(), "the pool did not shrink back to minimumIdle");
            assertEquals(2, pool.totalCount());
            assertTrue(pool.statistics().retired() >= 6,
                    "the surplus connections were not closed: " + pool.statistics());

            // And it stays stable at two - no oscillating between closing
            // and refilling.
            Thread.sleep(700);
            assertEquals(2, pool.idleCount(), "the pool oscillates: " + pool.statistics());
        }
    }

    @Test
    void warmupOpensTheConnectionsUpFront() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings(5);
        settings.setMinimumIdle(3);
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            pool.warmup();
            assertEquals(3, source.openedCount());
            assertEquals(3, pool.idleCount());
            assertEquals(0, pool.activeCount());
        }
    }

    /** If the connect fails there is no way out - and no lost permit. */
    @Test
    void aFailedConnectAttemptReleasesItsPermit() throws Exception {
        StubDataSource source = new StubDataSource();
        source.failWith(new SQLNonTransientConnectionException("the database is down", "08006"));
        try (SeclumePool pool = new SeclumePool(source, settings(1))) {
            assertThrows(SQLException.class, pool::getConnection);
            assertEquals(0, pool.activeCount(), "the permit was not released");

            // And when the database comes back, things carry on.
            source.succeedAgain();
            try (Connection connection = pool.getConnection()) {
                assertFalse(connection.isClosed());
            }
        }
    }

    @Test
    void closingThePoolClosesEveryConnection() throws Exception {
        StubDataSource source = new StubDataSource();
        SeclumePool pool = new SeclumePool(source, settings(3));
        pool.getConnection().close();
        pool.getConnection().close();
        Connection stillOut = pool.getConnection();
        pool.close();

        assertTrue(pool.isClosed());
        for (StubDataSource.StubConnection state : source.handedOut()) {
            assertTrue(state.closed.get(), "a connection survived the pool");
        }
        assertThrows(SQLException.class, pool::getConnection);
        // The one still borrowed must not blow up when it is returned.
        stillOut.close();
    }

    /** The pool takes no password - not by this route either. */
    @Test
    void refusesTheUserAndPasswordCall() {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings(1))) {
            SQLException failure = assertThrows(SQLFeatureNotSupportedException.class,
                    () -> pool.getConnection("app", "geheim"));
            assertTrue(failure.getMessage().contains("heap"), failure.getMessage());
        }
    }

    /** A pool dump ends up in logs - it may contain only numbers. */
    @Test
    void theStatisticsCarryNothingConfidential() throws Exception {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings(2))) {
            pool.getConnection().close();
            String text = pool.toString();
            assertTrue(text.contains("total=1"), text);
            assertFalse(text.toLowerCase(java.util.Locale.ROOT).contains("password"), text);
            assertFalse(text.toLowerCase(java.util.Locale.ROOT).contains("provider"), text);
            assertEquals(1, pool.statistics().created());
            assertEquals(1, pool.statistics().borrowed());
        }
    }

    /** Many virtual threads at once - none of them may lose a connection. */
    @Test
    void survivesManyVirtualThreads() throws Exception {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings(8);
        settings.setConnectionTimeout(Duration.ofSeconds(10));
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            int threads = 500;
            CountDownLatch finished = new CountDownLatch(threads);
            AtomicInteger failures = new AtomicInteger();
            for (int i = 0; i < threads; i++) {
                Thread.ofVirtual().start(() -> {
                    try (Connection connection = pool.getConnection()) {
                        assertFalse(connection.isClosed());
                    } catch (Exception e) {
                        failures.incrementAndGet();
                    } finally {
                        finished.countDown();
                    }
                });
            }
            assertTrue(finished.await(30, TimeUnit.SECONDS), "the threads did not finish");
            assertEquals(0, failures.get(), "some threads did not get a connection");
            assertEquals(0, pool.activeCount(), "connections were lost");
            assertTrue(source.openedCount() <= 8,
                    "the pool opened " + source.openedCount() + " connections for a maximum of 8");
        }
    }
}
