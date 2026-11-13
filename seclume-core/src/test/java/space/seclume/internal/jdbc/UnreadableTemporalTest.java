package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLDataException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;

import org.junit.jupiter.api.Test;

/**
 * A value a temporal getter cannot read ends in a {@code SQLDataException}
 * with SQLSTATE 22007, as JDBC requires - not in the unchecked exception
 * of {@code Timestamp.valueOf}, {@code Date.valueOf} or {@code java.time}.
 *
 * <p>Review round 4: what servers send in ordinary use - MySQL's zero date
 * {@code 0000-00-00 00:00:00} where the SQL mode allows it, PostgreSQL's
 * {@code infinity} and {@code -infinity}, a year past 9999 - went through
 * {@code getTimestamp}, {@code getDate}, {@code getObject(i, LocalDateTime.class)}
 * and the rest as {@code IllegalArgumentException} or
 * {@code DateTimeParseException}, past an application's
 * {@code catch (SQLException e)}.
 */
class UnreadableTemporalTest {

    private static final String[] VALUES = {
            "0000-00-00 00:00:00", "0000-00-00", "infinity", "-infinity", "12345-01-01 00:00:00",
            "not a date at all"};

    private static ListResultSet rows(String... values) {
        List<Object[]> rows = new ArrayList<>();
        for (String value : values) {
            rows.add(new Object[] {value});
        }
        return new ListResultSet(new String[] {"value"}, new int[] {Types.VARCHAR},
                new String[] {"varchar"}, rows);
    }

    @Test
    void anUnreadableValueIsASqlDataException() throws Exception {
        Calendar utc = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        try (ListResultSet rows = rows(VALUES)) {
            while (rows.next()) {
                String value = rows.getString(1);
                List<Getter> getters = List.<Getter>of(
                        () -> rows.getTimestamp(1),
                        () -> rows.getTimestamp("value"),
                        () -> rows.getTimestamp(1, utc),
                        () -> rows.getDate(1),
                        () -> rows.getDate(1, utc),
                        () -> rows.getTime(1),
                        () -> rows.getObject(1, LocalDateTime.class),
                        () -> rows.getObject(1, LocalDate.class),
                        () -> rows.getObject(1, OffsetDateTime.class),
                        () -> rows.getObject(1, java.time.Instant.class),
                        () -> rows.getObject(1, Timestamp.class));
                for (int i = 0; i < getters.size(); i++) {
                    if (i == 5 && value.endsWith(" 00:00:00")) {
                        continue;                 // its time of day is readable: 00:00:00
                    }
                    SQLDataException refused = assertThrows(SQLDataException.class,
                            getters.get(i)::get, value + ", getter " + i);
                    assertEquals("22007", refused.getSQLState(), value);
                }
                // The row is still there to be read another way.
                assertEquals(value, rows.getString(1));
            }
        }
    }

    @Test
    void anUnreadableUuidIsASqlDataExceptionToo() throws Exception {
        try (ListResultSet rows = rows("not-a-uuid")) {
            assertTrue(rows.next());
            assertEquals("22007", assertThrows(SQLDataException.class,
                    () -> rows.getObject(1, UUID.class)).getSQLState());
        }
    }

    @Test
    void readableValuesAreReadAsBefore() throws Exception {
        try (ListResultSet rows = rows("2026-11-13 09:47:00.5", "2026-11-13")) {
            assertTrue(rows.next());
            assertEquals(Timestamp.valueOf("2026-11-13 09:47:00.5"), rows.getTimestamp(1));
            assertEquals(LocalDateTime.of(2026, 11, 13, 9, 47, 0, 500_000_000),
                    rows.getObject(1, LocalDateTime.class));
            assertTrue(rows.next());
            assertEquals(java.sql.Date.valueOf("2026-11-13"), rows.getDate(1));
        }
    }

    @FunctionalInterface
    private interface Getter {
        Object get() throws Exception;
    }
}
