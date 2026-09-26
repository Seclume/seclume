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
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            if (rows.next()) {
                long value = rows.getLong(1);
                return rows.wasNull() ? -1 : (int) Math.min(Integer.MAX_VALUE, value);
            }
            return -1;
        } catch (SQLException notVisible) {
            return -1;
        }
    }
}
