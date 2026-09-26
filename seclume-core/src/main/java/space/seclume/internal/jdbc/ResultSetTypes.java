package space.seclume.internal.jdbc;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;

/**
 * The result set types a statement can be asked for, and which of them there
 * are.
 *
 * <p>Two: {@code TYPE_FORWARD_ONLY}, and {@code TYPE_SCROLL_INSENSITIVE} - the
 * one Hibernate's {@code scroll()} asks for by default and reporting tools
 * open their queries with. A scrollable result is read whole, into the same
 * native block a forward-only one uses, and the cursor then moves over it in
 * any direction; no value is copied onto the heap for it.
 *
 * <p>Refused, and saying why: {@code TYPE_SCROLL_SENSITIVE}, which would have
 * to see changes made after the query, and any updatable concurrency. A
 * result that quietly behaves like another type than the one asked for is
 * worse than a refusal.
 */
public final class ResultSetTypes {

    private ResultSetTypes() {
    }

    /**
     * The type to run the statement with.
     *
     * @throws SQLFeatureNotSupportedException for a type or concurrency there is not
     */
    public static int require(int type, int concurrency) throws SQLException {
        if (concurrency == ResultSet.CONCUR_UPDATABLE) {
            throw new SQLFeatureNotSupportedException("seclume result sets are read-only - "
                    + "change data with an UPDATE statement");
        }
        if (concurrency != ResultSet.CONCUR_READ_ONLY) {
            throw new SQLException("not a result set concurrency: " + concurrency);
        }
        return switch (type) {
            case ResultSet.TYPE_FORWARD_ONLY, ResultSet.TYPE_SCROLL_INSENSITIVE -> type;
            case ResultSet.TYPE_SCROLL_SENSITIVE -> throw new SQLFeatureNotSupportedException(
                    "seclume reads a scrollable result whole and does not see later changes "
                            + "to it - ask for TYPE_SCROLL_INSENSITIVE");
            default -> throw new SQLException("not a result set type: " + type);
        };
    }

    /**
     * A fetch direction: forward, reverse or unknown, taken as the hint JDBC
     * says it is. Anything else is not a direction and is refused.
     */
    public static void requireDirection(int direction) throws SQLException {
        if (direction != ResultSet.FETCH_FORWARD && direction != ResultSet.FETCH_REVERSE
                && direction != ResultSet.FETCH_UNKNOWN) {
            throw new SQLException("not a fetch direction: " + direction, "HY024");
        }
    }
}
