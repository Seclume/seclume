package space.seclume.pool;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Prepared statements that outlive the borrow.
 *
 * <p>A framework builds a {@code PreparedStatement} for every operation and
 * closes it again - Spring Data does, Hibernate does, and so does most code
 * written by hand. Each of those closes tells the server to throw the plan
 * away, and the next call makes it parse the same text anew. The connection is
 * the same physical one either way; only the handle around it was thrown away.
 *
 * <p>So the pool keeps them. A statement that is given back goes into this
 * cache under its text, and the next {@code prepareStatement} with that text
 * gets it out again - reset, but already prepared on the server.
 *
 * <p><b>Two rules that make it safe.</b> A statement is handed out to one
 * borrower at a time: while it is out it is not in the cache, so the same text
 * prepared twice gives two different statements, as JDBC requires. And the
 * cache belongs to the physical connection, never to the pool as a whole - a
 * plan lives in a session and means nothing outside it.
 *
 * <p>Bounded, and the oldest goes first: a cache without a bound is a leak with
 * good manners, and applications that build statement text out of values would
 * otherwise fill it forever.
 */
final class StatementCache {

    private final int capacity;
    /** Access order, so that the least recently used one is the first to go. */
    private final Map<String, PreparedStatement> free;

    StatementCache(int capacity) {
        this.capacity = capacity;
        this.free = new LinkedHashMap<>(Math.max(16, capacity), 0.75f, true);
    }

    /**
     * A statement for this text, prepared or taken out of the cache.
     *
     * <p>Taken <b>out</b>: while a statement is in use it must not be in the
     * cache, or the same text prepared twice would hand out one object twice.
     */
    PreparedStatement take(Connection connection, String sql) throws SQLException {
        PreparedStatement cached = free.remove(sql);
        if (cached == null) {
            return fresh(connection, sql);
        }
        if (isUnusable(cached)) {
            closeQuietly(cached);
            return fresh(connection, sql);
        }
        return cached;
    }

    /**
     * What a statement is set to when it is new - the driver's defaults,
     * read once per statement and put back on every return.
     *
     * <p>The next borrower who prepares the same text gets this object, and
     * JDBC promises a new statement: one borrower's setMaxRows(1) left in
     * place gave the next one a single row of a result, silently, and a
     * query timeout of one second cut the next one's query short.
     */
    private record Settings(int maxRows, int queryTimeout, int fetchSize, int maxFieldSize,
                            int fetchDirection) {

        static Settings of(PreparedStatement statement) throws SQLException {
            return new Settings(statement.getMaxRows(), statement.getQueryTimeout(),
                    statement.getFetchSize(), statement.getMaxFieldSize(),
                    statement.getFetchDirection());
        }

        /** Puts back what differs - the getters are field reads, the setters may not be. */
        void restore(PreparedStatement statement) throws SQLException {
            if (statement.getMaxRows() != maxRows) {
                statement.setMaxRows(maxRows);
            }
            if (statement.getQueryTimeout() != queryTimeout) {
                statement.setQueryTimeout(queryTimeout);
            }
            if (statement.getFetchSize() != fetchSize) {
                statement.setFetchSize(fetchSize);
            }
            if (statement.getMaxFieldSize() != maxFieldSize) {
                statement.setMaxFieldSize(maxFieldSize);
            }
            if (statement.getFetchDirection() != fetchDirection) {
                statement.setFetchDirection(fetchDirection);
            }
        }
    }

    private final Map<PreparedStatement, Settings> settings = new java.util.IdentityHashMap<>();

    private PreparedStatement fresh(Connection connection, String sql) throws SQLException {
        PreparedStatement statement = connection.prepareStatement(sql);
        if (capacity > 0) {
            try {
                settings.put(statement, Settings.of(statement));
            } catch (SQLException | RuntimeException e) {
                // Not knowing its defaults, the cache will not keep it - see give.
            }
        }
        return statement;
    }

    /**
     * Takes a statement back instead of closing it.
     *
     * @return whether the cache kept it; {@code false} means the caller closes
     *         it as it always did
     */
    boolean give(String sql, PreparedStatement statement) {
        if (capacity <= 0 || sql == null) {
            return false;
        }
        try {
            // closeOnCompletion cannot be taken back - JDBC has no call for
            // it - so a statement that was told it would close under the
            // next borrower as soon as that one's result closed.
            if (statement.isCloseOnCompletion()) {
                settings.remove(statement);
                return false;
            }
            Settings fresh = settings.get(statement);
            if (fresh == null) {
                return false;                 // its defaults are not known
            }
            statement.clearParameters();
            statement.clearWarnings();
            statement.clearBatch();
            fresh.restore(statement);
        } catch (SQLException | RuntimeException e) {
            settings.remove(statement);
            // A statement that cannot even be reset has nothing to do in a
            // cache - it goes, and the next call prepares a fresh one.
            return false;
        }
        PreparedStatement previous = free.put(sql, statement);
        if (previous != null && previous != statement) {
            closeQuietly(previous);
        }
        evictWhileTooLarge();
        return true;
    }

    /** Whether this very statement waits in the cache - it is not a leak then. */
    boolean holds(java.sql.Statement statement) {
        for (PreparedStatement cached : free.values()) {
            if (cached == statement) {
                return true;
            }
        }
        return false;
    }

    /** Everything the cache holds - when the connection itself goes. */
    void closeAll() {
        List<PreparedStatement> all = new ArrayList<>(free.values());
        free.clear();
        for (PreparedStatement statement : all) {
            closeQuietly(statement);
        }
    }

    int size() {
        return free.size();
    }

    private void evictWhileTooLarge() {
        Iterator<Map.Entry<String, PreparedStatement>> oldest = free.entrySet().iterator();
        while (free.size() > capacity && oldest.hasNext()) {
            Map.Entry<String, PreparedStatement> entry = oldest.next();
            oldest.remove();
            closeQuietly(entry.getValue());
        }
    }

    private static boolean isUnusable(PreparedStatement statement) {
        try {
            return statement.isClosed();
        } catch (SQLException e) {
            return true;
        }
    }

    private void closeQuietly(PreparedStatement statement) {
        settings.remove(statement);
        try {
            statement.close();
        } catch (SQLException e) {
            // The connection is being given up anyway; a statement that will
            // not close cannot be helped and must not hide that.
        }
    }
}
