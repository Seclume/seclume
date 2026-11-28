package space.seclume.internal.jdbc;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;

import space.seclume.ServerCapacity;

/** The two numbers of {@link ServerCapacity}, each asked on its own. */
public final class Capacities {

    private Capacities() {
    }

    /**
     * Asks both, each separately: a user allowed to see the limit but not the
     * sessions - or neither - gets what it can see and -1 for the rest.
     */
    public static ServerCapacity.Capacity ask(Connection connection, String allowedSql,
                                              String inUseSql) {
        return new ServerCapacity.Capacity(number(connection, allowedSql),
                number(connection, inUseSql));
    }

    /**
     * A server's idle limit, read as one number in {@code unit}: null when the
     * server has none (zero, a null, no row) or the user may not see it.
     */
    public static Duration idleLimit(Connection connection, String sql, Duration unit) {
        int value = number(connection, sql);
        return value <= 0 ? null : unit.multipliedBy(value);
    }

    private static int number(Connection connection, String sql) {
        try (Statement statement = connection.createStatement()) {
            // A probe of the pool's own, on a connection nobody has yet: bounded,
            // or a server that never answers keeps the pool's slot for ever.
            statement.setQueryTimeout(PROBE_SECONDS);
            return first(statement.executeQuery(sql));
        } catch (SQLException notVisible) {
            return -1;
        }
    }

    /** {@code seclume.pool.probeSeconds}: how long a capacity or idle-limit probe may take. */
    static final int PROBE_SECONDS = Integer.getInteger("seclume.pool.probeSeconds", 5);

    private static int first(ResultSet result) throws SQLException {
        try (ResultSet rows = result) {
            if (rows.next()) {
                long value = rows.getLong(1);
                return rows.wasNull() ? -1 : (int) Math.min(Integer.MAX_VALUE, value);
            }
            return -1;
        }
    }
}
