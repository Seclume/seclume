package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * A connection that breaks while somebody is holding it.
 *
 * <p>One that breaks <b>in</b> the pool never reaches anybody - it is checked
 * before it goes out. This is the other case: a rollout, a firewall that
 * forgets the socket, a server that goes away between two statements, while an
 * application has the connection in its hand. Other pools can only pass the
 * failure on, because reconnecting needs the password and they would have to
 * keep it somewhere. Here the secret source is simply asked again.
 *
 * <p>So both halves are worth a test, and the second half is the important one:
 * <b>when it must not happen</b>. Quietly repeating a call whose outcome nobody
 * can establish is how a booking happens twice, and that is a worse failure than
 * the one being avoided.
 */
class RenewBrokenConnectionTest {

    private static PoolSettings settings() {
        PoolSettings settings = new PoolSettings();
        settings.setName("renew-test");
        settings.setMaximumPoolSize(4);
        settings.setConnectionTimeout(Duration.ofSeconds(5));
        // Out of the way: these tests break connections on purpose, and a check
        // on the way out would only hide which half is doing the work.
        settings.setValidationBypassWindow(Duration.ofMinutes(5));
        return settings;
    }

    /** The plain case: nothing open, so nobody can tell. */
    @Test
    void aConnectionThatBreaksBetweenStatementsIsRebuiltQuietly() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings());
             Connection connection = pool.getConnection()) {
            source.handedOut().get(0).broken = true;

            Statement statement = connection.createStatement();

            assertNotNull(statement, "the call came back empty instead of on a new connection");
            assertEquals(2, source.openedCount(), "no second connection was opened");
            assertEquals(1, pool.statistics().renewed());
            assertTrue(source.handedOut().get(0).closed.get(),
                    "the broken connection was left open");
        }
    }

    /** And what it kept on the way: the settings this connection was given. */
    @Test
    void theNewConnectionIsSetUpLikeTheOldOne() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings());
             Connection connection = pool.getConnection()) {
            connection.setReadOnly(true);
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            connection.setCatalog("books");
            connection.setSchema("shop");

            source.handedOut().get(0).broken = true;
            connection.createStatement();

            StubDataSource.StubConnection fresh = source.handedOut().get(1);
            assertTrue(fresh.readOnly, "read-only was not set again");
            assertEquals(Connection.TRANSACTION_SERIALIZABLE, fresh.isolation,
                    "the isolation level was not set again");
            assertEquals("books", fresh.catalog, "the catalog was not set again");
            assertEquals("shop", fresh.schema, "the schema was not set again");
        }
    }

    /**
     * An open transaction is where it stops.
     *
     * <p>What was written before the break is gone, and nobody can say what of
     * it arrived. Carrying on quietly would mean the application finishes a
     * transaction that lost its beginning.
     */
    @Test
    void insideATransactionTheFailureGoesThrough() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings());
             Connection connection = pool.getConnection()) {
            connection.setAutoCommit(false);
            connection.createStatement().close();      // work, and it is done with
            source.handedOut().get(0).broken = true;

            SQLException thrown = assertThrows(SQLException.class, connection::createStatement);

            assertEquals("08006", thrown.getSQLState());
            assertEquals(1, source.openedCount(), "a connection was rebuilt under a transaction");
            assertEquals(0, pool.statistics().renewed());
        }
    }

    /** A statement still in the hand of the application belongs to the connection that is gone. */
    @Test
    void withAnOpenStatementTheFailureGoesThrough() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings());
             Connection connection = pool.getConnection()) {
            Statement open = connection.createStatement();
            assertNotNull(open);
            source.handedOut().get(0).broken = true;

            assertThrows(SQLException.class, connection::createStatement);
            assertEquals(1, source.openedCount(),
                    "rebuilt while the application still held a statement");
        }
    }

    /** A savepoint is a transaction with a shape - the same line. */
    @Test
    void withASavepointTheFailureGoesThrough() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings());
             Connection connection = pool.getConnection()) {
            connection.setAutoCommit(false);
            connection.setSavepoint("half-way");
            source.handedOut().get(0).broken = true;

            assertThrows(SQLException.class, connection::createStatement);
            assertEquals(1, source.openedCount(), "rebuilt under a standing savepoint");
        }
    }

    /** Once per borrow: a second break straight after is a server that is gone. */
    @Test
    void itIsRebuiltOnceAndNotAgain() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings());
             Connection connection = pool.getConnection()) {
            source.handedOut().get(0).broken = true;
            connection.createStatement().close();
            assertEquals(2, source.openedCount());

            source.handedOut().get(1).broken = true;
            SQLException thrown = assertThrows(SQLException.class, connection::createStatement);

            assertEquals("08006", thrown.getSQLState());
            assertEquals(2, source.openedCount(), "it kept rebuilding instead of giving up");
        }
    }

    /** A failure that says nothing about the connection is nobody's business here. */
    @Test
    void anOrdinaryErrorIsNotACauseToRebuild() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings());
             Connection connection = pool.getConnection()) {
            // The stub answers nothing it was not taught - a plain SQLException
            // without a connection state, which is what a syntax error is.
            assertThrows(SQLException.class, () -> connection.nativeSQL("select 1"));
            assertEquals(1, source.openedCount(), "rebuilt because of a syntax error");
        }
    }

    /** Switched off, the old behaviour is back: the failure belongs to the application. */
    @Test
    void switchedOffNothingIsRebuilt() throws SQLException {
        StubDataSource source = new StubDataSource();
        PoolSettings settings = settings();
        settings.setRenewBrokenConnections(false);
        try (SeclumePool pool = new SeclumePool(source, settings);
             Connection connection = pool.getConnection()) {
            source.handedOut().get(0).broken = true;

            assertThrows(SQLException.class, connection::createStatement);
            assertEquals(1, source.openedCount());
        }
    }

    /** And a pool that cannot open anything tells the first failure, not the second. */
    @Test
    void whenTheServerIsGoneTheOriginalFailureIsTheOneTold() throws SQLException {
        StubDataSource source = new StubDataSource();
        try (SeclumePool pool = new SeclumePool(source, settings());
             Connection connection = pool.getConnection()) {
            source.handedOut().get(0).broken = true;
            source.failWith(new SQLException("nothing answers at all", "08001"));

            SQLException thrown = assertThrows(SQLException.class, connection::createStatement);

            assertEquals("08006", thrown.getSQLState(),
                    "the failure the application saw was the rebuild, not the break");
            assertEquals(1, thrown.getSuppressed().length,
                    "the rebuild attempt was dropped instead of being attached");
            assertNotSame(thrown, thrown.getSuppressed()[0]);
        }
    }
}
