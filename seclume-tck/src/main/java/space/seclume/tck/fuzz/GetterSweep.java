package space.seclume.tck.fuzz;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

/**
 * Every getter on every column of every row of an answer, for a fuzz test
 * that has got as far as a ResultSet: a decoder's test stops at the first
 * value, read as a string, and the converters behind the getters - numbers,
 * dates, bytes, UUIDs, arrays - meet the server's bytes there. A getter may
 * refuse a value with an SQLException; anything else it lets out is what
 * {@link SessionContract} calls a breach.
 */
public final class GetterSweep {

    private GetterSweep() {
    }

    /** One way of reading a column. */
    @FunctionalInterface
    public interface Getter {
        Object read(ResultSet rows, int column) throws SQLException;
    }

    /** The getters a driver's converters sit behind. */
    public static final List<Getter> GETTERS = List.of(
            ResultSet::getString, ResultSet::getBoolean, ResultSet::getByte,
            ResultSet::getShort, ResultSet::getInt, ResultSet::getLong, ResultSet::getFloat,
            ResultSet::getDouble, ResultSet::getBigDecimal, ResultSet::getBytes,
            ResultSet::getDate, ResultSet::getTime, ResultSet::getTimestamp,
            ResultSet::getObject, ResultSet::getArray,
            (rows, column) -> rows.getObject(column, java.time.LocalDate.class),
            (rows, column) -> rows.getObject(column, java.time.LocalTime.class),
            (rows, column) -> rows.getObject(column, java.time.LocalDateTime.class),
            (rows, column) -> rows.getObject(column, java.time.OffsetDateTime.class),
            (rows, column) -> rows.getObject(column, java.util.UUID.class));

    /**
     * Runs {@code sql} and reads every column of every row with every getter.
     * A getter's SQLException is allowed and passed over; one from running the
     * query or moving through the rows ends the attempt as a refusal.
     */
    public static void readEverything(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            int columns = rows.getMetaData().getColumnCount();
            while (rows.next()) {
                for (int column = 1; column <= columns; column++) {
                    for (Getter getter : GETTERS) {
                        try {
                            getter.read(rows, column);
                        } catch (SQLException refused) {
                            // A value this getter does not take: allowed.
                        }
                    }
                }
            }
        }
    }
}
