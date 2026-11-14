package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The statement cache on its own, with statements that answer like a driver's.
 *
 * <p>What it must never do is hand one borrower's statement to the next in
 * the state that borrower left it: a {@code setMaxRows(1)} or a one-second
 * query timeout carried over cuts the next borrower's result or query short,
 * silently. And it must never hand out one statement twice. Before these
 * tests, {@code give} could have answered {@code true} for everything, or
 * {@code false} for everything, and no test under PIT would have noticed
 * (run 43416680859: eight survivors in {@code StatementCache}).
 */
class StatementCacheTest {

    private static final String SQL = "select name from customer where id = ?";

    @Test
    void aStatementGivenBackIsTheOneTheNextTakeGets() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        StatementCache cache = new StatementCache(4);
        PreparedStatement first = cache.take(connection.connection, SQL);
        assertTrue(cache.give(SQL, first), "a statement with known defaults is kept");
        assertEquals(1, cache.size());
        assertTrue(cache.holds(first));

        PreparedStatement again = cache.take(connection.connection, SQL);
        assertSame(first, again, "prepared once on the server, reused");
        assertEquals(1, connection.prepared.size());
        assertEquals(0, cache.size(), "taken out while it is in use");
        assertFalse(cache.holds(first));
    }

    /** JDBC promises a new statement for each prepare: never one object to two callers. */
    @Test
    void theSameTextPreparedTwiceGivesTwoStatements() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        StatementCache cache = new StatementCache(4);
        PreparedStatement one = cache.take(connection.connection, SQL);
        PreparedStatement two = cache.take(connection.connection, SQL);
        assertNotSame(one, two);
        assertEquals(2, connection.prepared.size());

        assertTrue(cache.give(SQL, one));
        assertTrue(cache.give(SQL, two), "the later one takes the place");
        assertEquals(1, cache.size());
        assertEquals(1, connection.prepared.get(0).closes.get(), "the displaced one is closed, not leaked");
        assertEquals(0, connection.prepared.get(1).closes.get());
        assertTrue(cache.holds(two));
        assertFalse(cache.holds(one));
    }

    @Test
    void givingTheSameStatementBackTwiceDoesNotCloseIt() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        StatementCache cache = new StatementCache(4);
        PreparedStatement one = cache.take(connection.connection, SQL);
        assertTrue(cache.give(SQL, one));
        assertTrue(cache.give(SQL, one));
        assertEquals(0, connection.prepared.getFirst().closes.get());
        assertEquals(1, cache.size());
    }

    /** What one borrower set does not reach the next one. */
    @Test
    void whatABorrowerChangedIsPutBackToTheDriversDefaults() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        connection.defaults = statement -> {
            statement.fetchSize = 50;
            statement.maxFieldSize = 65535;
        };
        StatementCache cache = new StatementCache(4);
        PreparedStatement statement = cache.take(connection.connection, SQL);
        FakePreparedStatement fake = connection.prepared.getFirst();
        fake.setters.clear();

        statement.setMaxRows(1);
        statement.setQueryTimeout(1);
        statement.setFetchSize(7);
        statement.setMaxFieldSize(16);
        statement.setFetchDirection(ResultSet.FETCH_REVERSE);
        fake.setters.clear();
        assertTrue(cache.give(SQL, statement));

        assertEquals(0, fake.maxRows, "maxRows");
        assertEquals(0, fake.queryTimeout, "queryTimeout");
        assertEquals(50, fake.fetchSize, "fetchSize - the driver's default, not 0");
        assertEquals(65535, fake.maxFieldSize, "maxFieldSize - the driver's default, not 0");
        assertEquals(ResultSet.FETCH_FORWARD, fake.fetchDirection, "fetchDirection");
        assertEquals(1, fake.clearParameters.get(), "the last borrower's values are not bound any more");
        assertEquals(1, fake.clearWarnings.get());
        assertEquals(1, fake.clearBatch.get(), "a batch left behind is not run by the next borrower");
        assertEquals(List.of("setMaxRows", "setQueryTimeout", "setFetchSize", "setMaxFieldSize",
                "setFetchDirection"), fake.setters);
    }

    @Test
    void aStatementLeftAsItWasIsNotSetAgain() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        StatementCache cache = new StatementCache(4);
        PreparedStatement statement = cache.take(connection.connection, SQL);
        FakePreparedStatement fake = connection.prepared.getFirst();
        assertTrue(cache.give(SQL, statement));
        assertEquals(List.of(), fake.setters, "a setter may be a round trip; nothing differs");
    }

    /** closeOnCompletion cannot be undone: kept, it would close under the next borrower. */
    @Test
    void aStatementToldToCloseOnCompletionIsNotKept() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        StatementCache cache = new StatementCache(4);
        PreparedStatement statement = cache.take(connection.connection, SQL);
        statement.closeOnCompletion();
        assertFalse(cache.give(SQL, statement));
        assertEquals(0, cache.size());
        assertEquals(0, connection.prepared.getFirst().closes.get(), "the caller closes it, as always");
    }

    @Test
    void aStatementWhoseDefaultsAreUnknownIsNotKept() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        connection.defaults = statement -> statement.failing.add("getMaxRows");
        StatementCache cache = new StatementCache(4);
        PreparedStatement statement = cache.take(connection.connection, SQL);
        connection.prepared.getFirst().failing.clear();
        assertFalse(cache.give(SQL, statement), "it could not be put back to defaults nobody knows");
        assertEquals(0, cache.size());

        PreparedStatement foreign = new FakePreparedStatement().proxy;
        assertFalse(cache.give(SQL, foreign), "not prepared through this cache: its defaults are unknown");
    }

    @Test
    void aStatementThatCannotBeResetIsNotKeptAndItsDefaultsAreForgotten() throws SQLException {
        for (String broken : List.of("clearParameters", "clearWarnings", "clearBatch", "setMaxRows",
                "isCloseOnCompletion")) {
            for (boolean unchecked : new boolean[] {false, true}) {
                FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
                StatementCache cache = new StatementCache(4);
                PreparedStatement statement = cache.take(connection.connection, SQL);
                FakePreparedStatement fake = connection.prepared.getFirst();
                statement.setMaxRows(3);
                (unchecked ? fake.failingUnchecked : fake.failing).add(broken);
                assertFalse(cache.give(SQL, statement), broken);
                assertEquals(0, cache.size(), broken);

                // Forgotten for good: even working again, it is not taken back.
                fake.failing.clear();
                fake.failingUnchecked.clear();
                assertFalse(cache.give(SQL, statement), broken + ", given back a second time");
            }
        }
    }

    @Test
    void noCapacityOrNoTextKeepsNothing() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        StatementCache none = new StatementCache(0);
        PreparedStatement statement = none.take(connection.connection, SQL);
        FakePreparedStatement fake = connection.prepared.getFirst();
        assertFalse(none.give(SQL, statement));
        assertEquals(0, fake.clearParameters.get(), "a cache that keeps nothing does not touch it");

        StatementCache cache = new StatementCache(4);
        PreparedStatement kept = cache.take(connection.connection, SQL);
        assertFalse(cache.give(null, kept), "a statement without its text cannot be found again");
        assertEquals(0, connection.prepared.get(1).clearParameters.get());
        assertEquals(0, cache.size());
    }

    @Test
    void theOneUsedLongestAgoGoesFirstAndIsClosed() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        StatementCache cache = new StatementCache(2);
        PreparedStatement a = cache.take(connection.connection, "a");
        PreparedStatement b = cache.take(connection.connection, "b");
        PreparedStatement c = cache.take(connection.connection, "c");
        assertTrue(cache.give("a", a));
        assertTrue(cache.give("b", b));
        assertEquals(2, cache.size());

        // a is used again, so b is now the least recently used one
        PreparedStatement a2 = cache.take(connection.connection, "a");
        assertSame(a, a2);
        assertTrue(cache.give("a", a2));
        assertTrue(cache.give("c", c));
        assertEquals(2, cache.size(), "bounded");
        assertTrue(cache.holds(a));
        assertTrue(cache.holds(c));
        assertFalse(cache.holds(b));
        assertEquals(1, connection.prepared.get(1).closes.get(), "the evicted one is closed on the server");
        assertEquals(0, connection.prepared.get(0).closes.get());
        assertEquals(0, connection.prepared.get(2).closes.get());
    }

    @Test
    void aCachedStatementThatWasClosedIsReplacedByAFreshOne() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        StatementCache cache = new StatementCache(4);
        PreparedStatement first = cache.take(connection.connection, SQL);
        assertTrue(cache.give(SQL, first));
        connection.prepared.getFirst().closed = true;           // the driver closed it underneath

        PreparedStatement next = cache.take(connection.connection, SQL);
        assertNotSame(first, next);
        assertEquals(2, connection.prepared.size());
        assertEquals(1, connection.prepared.getFirst().closes.get(), "closed through the cache too");

        assertTrue(cache.give(SQL, next));
        connection.prepared.get(1).failing.add("isClosed");      // cannot even say
        PreparedStatement third = cache.take(connection.connection, SQL);
        assertNotSame(next, third, "a statement that cannot say whether it is open is not reused");
    }

    @Test
    void closeAllClosesEveryStatementAndEmptiesTheCache() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        StatementCache cache = new StatementCache(4);
        PreparedStatement a = cache.take(connection.connection, "a");
        PreparedStatement b = cache.take(connection.connection, "b");
        assertTrue(cache.give("a", a));
        assertTrue(cache.give("b", b));
        connection.prepared.get(1).failing.add("close");         // one refuses: the rest still close

        cache.closeAll();
        assertEquals(0, cache.size());
        assertFalse(cache.holds(a));
        assertFalse(cache.holds(b));
        assertEquals(1, connection.prepared.get(0).closes.get());

        // Nothing is handed out again after the connection went.
        PreparedStatement fresh = cache.take(connection.connection, "a");
        assertNotSame(a, fresh);
        cache.closeAll();
        assertEquals(1, connection.prepared.get(0).closes.get(), "closed once, not again");
    }
}
