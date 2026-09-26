package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import space.seclume.tck.TestHosts;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.postgresql.jdbc.SeclumeDataSource;
import space.seclume.secret.FileSecretProvider;

/**
 * The pool with a real driver against a real database.
 *
 * <p>The mechanics live in {@code PoolTest} and run without a server. This is
 * about the assumptions one can only check on the living object: that a reused
 * connection really is the same session, that the reset state actually reaches
 * the server, and that under many virtual threads the pool opens no more
 * sessions than allowed.
 *
 * <p>The password arrives through the {@link FileSecretProvider} - the pool
 * itself never sees it.
 */
class PoolWithPostgresTest {

    private static Path passwordFile;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(passwordFile != null, TestHosts.postgresPasswordFile() + " is not there");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(TestHosts.postgres(), TestHosts.postgresPort()), 1000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on "
                    + TestHosts.postgres() + ":" + TestHosts.postgresPort());
        }
    }

    private static SeclumeDataSource dataSource() {
        SeclumeDataSource source = new SeclumeDataSource();
        source.setHost(TestHosts.postgres());
        source.setPort(TestHosts.postgresPort());
        source.setDatabase("seclume_test");
        source.setUser("seclume_test");
        source.setSecretProvider(new FileSecretProvider(passwordFile, 256));
        return source;
    }

    private static PoolSettings settings(int max) {
        PoolSettings settings = new PoolSettings();
        settings.setName("pg-test");
        settings.setMaximumPoolSize(max);
        settings.setConnectionTimeout(Duration.ofSeconds(10));
        return settings;
    }

    /** The same connection means the same session, and the server knows it. */
    @Test
    void reuseMeansTheSameServerSession() throws Exception {
        try (SeclumePool pool = new SeclumePool(dataSource(), settings(1))) {
            long first = backendPid(pool);
            long second = backendPid(pool);
            assertEquals(first, second, "the pool opened a second session");
            assertEquals(1, pool.statistics().created());
            assertEquals(2, pool.statistics().borrowed());
        }
    }

    /**
     * The server kills the session while it lies in the pool - and the
     * application sees nothing of it.
     *
     * <p>This is what stage 1 of the resilience notes is worth in
     * practice: after a restart or a rolling update the connections in the
     * pool are dead, and the first user afterwards did nothing wrong. The pool
     * asks a connection that has been lying around whether it is still there,
     * and quietly opens a new one when it is not.
     *
     * <p>The validation window is set to zero here on purpose. In normal
     * operation a connection that came back microseconds ago is not asked -
     * that round trip is the difference between a pool that costs a fraction
     * of a microsecond and one that costs sixty.
     */
    @Test
    void aSessionKilledWhileIdleIsReplacedWithoutTheApplicationNoticing() throws Exception {
        PoolSettings settings = settings(1);
        settings.setValidationBypassWindow(Duration.ZERO);
        try (SeclumePool pool = new SeclumePool(dataSource(), settings)) {
            long first = backendPid(pool);
            killEverySessionExceptMine(first);

            long second = backendPid(pool);
            assertTrue(second != first, "the dead session was handed out again");
            assertEquals(2, pool.statistics().created(),
                    "the pool should have opened exactly one replacement");
        }
    }

    /** Ends the pooled session from a connection of its own. */
    private static void killEverySessionExceptMine(long pid) throws Exception {
        try (Connection connection = dataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("select pg_terminate_backend(" + pid + ")");
        }
    }

    /**
     * A cached statement survives the borrow - and the server keeps its plan.
     *
     * <p>Proven by asking the server: {@code pg_prepared_statements} lists what
     * this session has prepared. Without the cache the entry is gone as soon as
     * the statement is closed, and the next call makes the server parse the
     * same text again.
     */
    @Test
    void aCachedStatementStaysPreparedOnTheServer() throws Exception {
        PoolSettings settings = settings(1);
        settings.setStatementCacheSize(8);
        try (SeclumePool pool = new SeclumePool(dataSource(), settings)) {
            String sql = "select 1 where 1 = ?";
            try (Connection connection = pool.getConnection();
                 PreparedStatement query = connection.prepareStatement(sql)) {
                query.setInt(1, 1);
                try (ResultSet rows = query.executeQuery()) {
                    assertTrue(rows.next());
                }
            }
            // The connection went back to the pool, and so did the statement.
            try (Connection connection = pool.getConnection()) {
                assertEquals(1, preparedOnServer(connection),
                        "the server should still hold the plan");
                try (PreparedStatement again = connection.prepareStatement(sql)) {
                    again.setInt(1, 1);
                    try (ResultSet rows = again.executeQuery()) {
                        assertTrue(rows.next());
                    }
                    assertEquals(1, preparedOnServer(connection),
                            "the second prepare must not make a second plan");
                }
            }
        }
    }

    /**
     * There are two caches, and switching off the pool's leaves the driver's.
     *
     * <p>This test used to assert that nothing at all is kept once the pool's
     * cache is off, and that was true while the driver had no cache of its own.
     * It has one now, so the two are worth keeping apart: the pool reuses the
     * <b>JDBC statement object</b> across borrows, the driver keeps the
     * <b>server-side plan</b> on the connection. Turning off the pool's saves
     * the wrapper; the plan survives, which is the whole point of the driver's.
     */
    @Test
    void withoutThePoolsCacheTheDriverStillKeepsThePlan() throws Exception {
        PoolSettings off = settings(1);
        off.setStatementCacheSize(0);
        try (SeclumePool pool = new SeclumePool(dataSource(), off)) {
            runOnce(pool, "select 2 where 2 = ?");
            try (Connection connection = pool.getConnection()) {
                assertEquals(1, preparedOnServer(connection),
                        "the driver keeps the plan even when the pool keeps nothing");
            }
        }
    }

    /** With both switched off, a closed statement takes its plan with it. */
    @Test
    void withNeitherCacheNothingStaysPrepared() throws Exception {
        PoolSettings off = settings(1);
        off.setStatementCacheSize(0);
        SeclumeDataSource source = dataSource();
        source.setStatementCacheSize(0);
        try (SeclumePool pool = new SeclumePool(source, off)) {
            runOnce(pool, "select 2 where 2 = ?");
            try (Connection connection = pool.getConnection()) {
                assertEquals(0, preparedOnServer(connection),
                        "a closed statement should have taken its plan with it");
            }
        }
    }

    /** Borrows a connection, runs the statement once, gives everything back. */
    private static void runOnce(SeclumePool pool, String sql) throws Exception {
        try (Connection connection = pool.getConnection();
             PreparedStatement query = connection.prepareStatement(sql)) {
            query.setInt(1, 2);
            try (ResultSet rows = query.executeQuery()) {
                assertTrue(rows.next());
            }
        }
    }

    /** The same text twice at once has to give two statements, as JDBC says. */
    @Test
    void theSameTextTwiceAtOnceGivesTwoStatements() throws Exception {
        PoolSettings settings = settings(1);
        settings.setStatementCacheSize(8);
        try (SeclumePool pool = new SeclumePool(dataSource(), settings);
             Connection connection = pool.getConnection()) {
            String sql = "select 3 where 3 = ?";
            try (PreparedStatement first = connection.prepareStatement(sql);
                 PreparedStatement second = connection.prepareStatement(sql)) {
                assertNotSame(first, second, "one object handed out twice");
                first.setInt(1, 3);
                second.setInt(1, 4);
                try (ResultSet rows = first.executeQuery()) {
                    assertTrue(rows.next(), "the first statement lost its value");
                }
                try (ResultSet rows = second.executeQuery()) {
                    assertFalse(rows.next(), "the second statement lost its value");
                }
            }
        }
    }

    /** A handle that was given back behaves as closed, whatever the cache does. */
    @Test
    void aClosedHandleRefusesToWork() throws Exception {
        PoolSettings settings = settings(1);
        settings.setStatementCacheSize(8);
        try (SeclumePool pool = new SeclumePool(dataSource(), settings);
             Connection connection = pool.getConnection()) {
            PreparedStatement query = connection.prepareStatement("select 4 where 4 = ?");
            query.close();
            assertTrue(query.isClosed());
            assertThrows(SQLException.class, query::executeQuery);
        }
    }

    /**
     * closeOnCompletion cannot be taken back, so a statement told it must not
     * reach the next borrower: its result closing would close the statement
     * under somebody who never asked for that.
     */
    @Test
    void aStatementToldToCloseOnCompletionIsNotCached() throws Exception {
        PoolSettings settings = settings(1);
        settings.setStatementCacheSize(8);
        try (SeclumePool pool = new SeclumePool(dataSource(), settings);
             Connection connection = pool.getConnection()) {
            String sql = "select 5 where 5 = ?";
            try (PreparedStatement told = connection.prepareStatement(sql)) {
                told.closeOnCompletion();
                told.setInt(1, 5);
                // Not closed by the application: the handle goes back with the
                // flag set, and the result is left for the handle's close.
                told.executeQuery();
            }
            PreparedStatement next = connection.prepareStatement(sql);
            assertFalse(next.isCloseOnCompletion(), "the flag came along to the next borrower");
            next.setInt(1, 5);
            try (ResultSet rows = next.executeQuery()) {
                assertTrue(rows.next());
            }
            assertFalse(next.isClosed(), "closed under a borrower who did not ask for it");
            next.close();
        }
    }

    /** A network timeout one borrower set does not reach the next one. */
    @Test
    void aNetworkTimeoutEndsWithTheBorrow() throws Exception {
        try (SeclumePool pool = new SeclumePool(dataSource(), settings(1))) {
            try (Connection connection = pool.getConnection()) {
                assertEquals(0, connection.getNetworkTimeout());
                connection.setNetworkTimeout(Runnable::run, 700);
                assertEquals(700, connection.getNetworkTimeout());
            }
            try (Connection connection = pool.getConnection();
                 Statement statement = connection.createStatement()) {
                assertEquals(0, connection.getNetworkTimeout(), "the timeout came along");
                // And it really is gone underneath: a second is longer than 700 ms.
                statement.execute("select pg_sleep(1)");
            }
        }
    }

    /** What this session has prepared, as the server sees it. */
    private static int preparedOnServer(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select count(*) from pg_prepared_statements")) {
            rows.next();
            return rows.getInt(1);
        }
    }

    private static long backendPid(SeclumePool pool) throws Exception {
        try (Connection connection = pool.getConnection();
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("select pg_backend_pid()")) {
            assertTrue(result.next());
            return result.getLong(1);
        }
    }

    /** The reset state has to reach the server, not just the wrapper. */
    @Test
    void theServerSeesTheResetState() throws Exception {
        try (SeclumePool pool = new SeclumePool(dataSource(), settings(1))) {
            try (Connection connection = pool.getConnection()) {
                connection.setAutoCommit(false);
                try (Statement statement = connection.createStatement()) {
                    statement.execute("create temporary table seclume_pool_probe (n int)");
                    statement.execute("insert into seclume_pool_probe values (1)");
                }
                // No commit - returning it has to roll back.
            }
            try (Connection connection = pool.getConnection()) {
                assertTrue(connection.getAutoCommit(), "autoCommit was not restored");
                assertFalse(connection.isReadOnly());
                try (Statement statement = connection.createStatement();
                     ResultSet result = statement.executeQuery(
                             "select count(*) from pg_class where relname = 'seclume_pool_probe'")) {
                    assertTrue(result.next());
                    assertEquals(0, result.getInt(1),
                            "the rolled-back temporary table is still there");
                }
            }
        }
    }

    /** A pool of eight connections may never open more than eight sessions. */
    @Test
    void manyVirtualThreadsShareEightSessions() throws Exception {
        PoolSettings settings = settings(8);
        settings.setConnectionTimeout(Duration.ofSeconds(30));
        try (SeclumePool pool = new SeclumePool(dataSource(), settings)) {
            int threads = 200;
            Set<Long> sessions = ConcurrentHashMap.newKeySet();
            CountDownLatch finished = new CountDownLatch(threads);
            AtomicInteger failures = new AtomicInteger();

            for (int i = 0; i < threads; i++) {
                Thread.ofVirtual().start(() -> {
                    try (Connection connection = pool.getConnection();
                         Statement statement = connection.createStatement();
                         ResultSet result = statement.executeQuery(
                                 "select pg_backend_pid()")) {
                        if (result.next()) {
                            sessions.add(result.getLong(1));
                        }
                    } catch (Exception e) {
                        failures.incrementAndGet();
                    } finally {
                        finished.countDown();
                    }
                });
            }
            assertTrue(finished.await(60, TimeUnit.SECONDS), "the threads did not finish");
            assertEquals(0, failures.get(), "some threads failed");
            assertTrue(sessions.size() <= 8,
                    "the pool used " + sessions.size() + " server sessions for a maximum of 8");
            assertEquals(0, pool.activeCount(), "connections were lost");
            assertEquals(200, pool.statistics().borrowed());
        }
    }

    @Test
    void warmupOpensTheSessionsUpFront() throws Exception {
        PoolSettings settings = settings(4);
        settings.setMinimumIdle(2);
        try (SeclumePool pool = new SeclumePool(dataSource(), settings)) {
            pool.warmup();
            assertEquals(2, pool.idleCount());
            assertEquals(2, pool.statistics().created());
            try (Connection connection = pool.getConnection()) {
                assertTrue(connection.isValid(2));
            }
            // No third session was opened.
            assertEquals(2, pool.statistics().created());
        }
    }

    /** After closing the pool the sessions are gone at the server. */
    @Test
    void closingThePoolEndsTheSessions() throws Exception {
        long pid;
        SeclumePool pool = new SeclumePool(dataSource(), settings(2));
        try {
            pid = backendPid(pool);
        } finally {
            pool.close();
        }

        // A second connection of its own asks the server about the old session.
        try (Connection connection = dataSource().getConnection();
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "select count(*) from pg_stat_activity where pid = " + pid)) {
            assertTrue(result.next());
            assertEquals(0, result.getInt(1), "the session outlived the pool");
        }
    }

    /** The wrapper is a real connection - JDBC code notices no difference. */
    @Test
    void behavesLikeAPlainConnection() throws Exception {
        try (SeclumePool pool = new SeclumePool(dataSource(), settings(2));
             Connection connection = pool.getConnection()) {
            assertSame(connection, connection.unwrap(Connection.class));
            assertEquals("PostgreSQL", connection.getMetaData().getDatabaseProductName());
            assertTrue(connection.isValid(2));
            assertFalse(connection.isClosed());
        }
    }
}
