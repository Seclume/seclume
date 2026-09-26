package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.postgresql.jdbc.SeclumeDataSource;
import space.seclume.secret.FileSecretProvider;
import space.seclume.tck.TestHosts;

/**
 * The pool's seam for handing a live connection on: {@link SeclumePool#detach}
 * lets go of one without closing it, {@link SeclumePool#adopt} takes one it
 * did not open. What moves between them is not the pool's business; that each
 * end keeps the pool's books straight is.
 */
class PoolHandOnSeamTest {

    private static Path passwordFile;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(passwordFile != null, TestHosts.postgresPasswordFile()
                + " is not there");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(TestHosts.postgres(), TestHosts.postgresPort()),
                    1000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + TestHosts.postgres() + ":"
                    + TestHosts.postgresPort());
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

    private static PoolSettings settings(int max, int statementCache) {
        PoolSettings settings = new PoolSettings();
        settings.setName("handon-test");
        settings.setMaximumPoolSize(max);
        settings.setStatementCacheSize(statementCache);
        settings.setConnectionTimeout(Duration.ofSeconds(10));
        return settings;
    }

    /**
     * Detached: the connection is still logged in and usable, the handle is
     * closed, and the slot is free.
     */
    @Test
    void aDetachedConnectionIsOpenAndNoLongerThePools() throws Exception {
        try (SeclumePool pool = new SeclumePool(dataSource(), settings(1, 8))) {
            Connection handle = pool.getConnection();
            String backend = ask(handle, "select pg_backend_pid()");
            try (PreparedStatement cached = handle.prepareStatement("select 1 + ?")) {
                cached.setInt(1, 1);
                cached.executeQuery().close();
            }

            Connection physical = pool.detach(handle);
            assertTrue(handle.isClosed(), "the handle still works after the detach");
            assertThrows(SQLException.class, () -> handle.createStatement());
            assertEquals(0, pool.totalCount(), "the pool still counts the connection");
            assertEquals(backend, ask(physical, "select pg_backend_pid()"),
                    "the connection handed out is not the one that was borrowed");
            // The pool closed its cached statement; the driver keeps the plan
            // in the physical connection's own cache, which is still this
            // connection's - so the same statement prepares and runs again.
            try (PreparedStatement again = physical.prepareStatement("select 1 + ?")) {
                again.setInt(1, 1);
                try (ResultSet rows = again.executeQuery()) {
                    rows.next();
                    assertEquals(2, rows.getInt(1));
                }
            }

            // The slot is free: a pool of one opens a new connection at once.
            try (Connection next = pool.getConnection()) {
                assertFalse(backend.equals(ask(next, "select pg_backend_pid()")));
            }
            assertThrows(SQLException.class, () -> pool.detach(handle),
                    "a handle can be given up once");
            assertTrue(pool.report().contains("handed on 1"), pool.report());
            physical.close();
        }
    }

    /**
     * Adopted in the middle of a transaction: the handle knows it, and
     * returning it rolls the transaction back and puts the pool's defaults
     * back, as for any other borrow.
     */
    @Test
    void anAdoptedConnectionIsReturnedLikeAnyOther() throws Exception {
        try (SeclumePool pool = new SeclumePool(dataSource(), settings(2, 0));
             Connection setup = dataSource().getConnection();
             Statement statement = setup.createStatement()) {
            statement.execute("drop table if exists zl_adopt");
            statement.execute("create table zl_adopt (n int)");
            pool.getConnection().close();              // so the pool knows its defaults

            Connection foreign = dataSource().getConnection();
            String backend = ask(foreign, "select pg_backend_pid()");
            foreign.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            foreign.setAutoCommit(false);
            try (Statement insert = foreign.createStatement()) {
                insert.executeUpdate("insert into zl_adopt values (1)");
            }

            Connection handle = pool.adopt(foreign);
            assertFalse(handle.getAutoCommit());
            assertEquals(backend, ask(handle, "select pg_backend_pid()"));
            assertEquals(2, pool.totalCount());
            handle.close();

            assertEquals("0", ask(setup, "select count(*) from zl_adopt"),
                    "returning the adopted connection did not roll its transaction back");
            assertTrue(foreign.getAutoCommit(), "auto-commit was not put back");
            assertEquals(Connection.TRANSACTION_READ_COMMITTED,
                    foreign.getTransactionIsolation(), "isolation was not put back");
            assertTrue(pool.report().contains("taken in 1"), pool.report());
            statement.execute("drop table zl_adopt");
        }
    }

    /** A pool does not grow past its size for a connection it was handed. */
    @Test
    void aFullPoolRefusesToAdopt() throws Exception {
        try (SeclumePool pool = new SeclumePool(dataSource(), settings(1, 0));
             Connection held = pool.getConnection();
             Connection foreign = dataSource().getConnection()) {
            SQLException refused = assertThrows(SQLException.class, () -> pool.adopt(foreign));
            assertTrue(refused.getMessage().contains("full"), refused.getMessage());
            assertEquals(1, pool.totalCount());
            assertFalse(foreign.isClosed(), "a refused connection is the caller's, untouched");
            assertTrue(held.isValid(1));
        }
    }

    @Test
    void aConnectionFromElsewhereCannotBeDetached() throws Exception {
        try (SeclumePool pool = new SeclumePool(dataSource(), settings(1, 0));
             Connection foreign = dataSource().getConnection()) {
            assertThrows(SQLException.class, () -> pool.detach(foreign));
        }
    }

    private static String ask(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }
}
