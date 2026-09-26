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
            return connection.prepareStatement(sql);
        }
        if (isUnusable(cached)) {
            closeQuietly(cached);
            return connection.prepareStatement(sql);
        }
        return cached;
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
                return false;
            }
            statement.clearParameters();
            statement.clearWarnings();
            statement.clearBatch();
        } catch (SQLException e) {
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

    private static void closeQuietly(PreparedStatement statement) {
        try {
            statement.close();
        } catch (SQLException e) {
            // The connection is being given up anyway; a statement that will
            // not close cannot be helped and must not hide that.
        }
    }
}
