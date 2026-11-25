package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

/**
 * A cached statement kept the result of its last execution: the next
 * borrower's getResultSet(), before it ran anything, was the previous
 * borrower's - another tenant's rows. What the last execution left is closed
 * before a statement is kept, and one that cannot say what is left is not
 * kept at all.
 */
class StatementCacheResultTest {

    private static final String SQL = "select balance from account where tenant = ?";

    private static ResultSet open(AtomicBoolean closed) {
        return (ResultSet) Proxy.newProxyInstance(ResultSet.class.getClassLoader(),
                new Class<?>[] {ResultSet.class}, (self, method, args) -> switch (method.getName()) {
                    case "close" -> {
                        closed.set(true);
                        yield null;
                    }
                    case "isClosed" -> closed.get();
                    case "hashCode" -> System.identityHashCode(self);
                    case "equals" -> self == args[0];
                    default -> null;
                });
    }

    @Test
    void theNextBorrowerSeesNoResultOfTheLast() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        StatementCache cache = new StatementCache(4);
        PreparedStatement taken = cache.take(connection.connection, SQL);
        FakePreparedStatement fake = connection.prepared.get(0);
        AtomicBoolean closed = new AtomicBoolean();
        fake.resultSet = open(closed);                        // tenant A's rows, unread
        assertTrue(cache.give(SQL, taken));
        assertTrue(closed.get(), "tenant A's result set was kept open in the cache");
    }

    @Test
    void moreResultsAreClosedBeforeAStatementIsKept() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        StatementCache cache = new StatementCache(4);
        PreparedStatement taken = cache.take(connection.connection, SQL);
        assertTrue(cache.give(SQL, taken));
        assertTrue(connection.prepared.get(0).moreResults.contains(Statement.CLOSE_ALL_RESULTS),
                "getMoreResults(CLOSE_ALL_RESULTS) was not called before the statement was kept");
    }

    @Test
    void aStatementThatCannotSayWhatIsLeftIsNotKept() throws SQLException {
        FakePreparedStatement.Preparing connection = new FakePreparedStatement.Preparing();
        StatementCache cache = new StatementCache(4);
        PreparedStatement taken = cache.take(connection.connection, SQL);
        connection.prepared.get(0).failing.add("getResultSet");
        assertFalse(cache.give(SQL, taken));
        assertFalse(cache.holds(taken));
    }
}
