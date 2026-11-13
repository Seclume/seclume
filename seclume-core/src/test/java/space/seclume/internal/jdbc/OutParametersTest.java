package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.math.BigDecimal;
import java.sql.Date;
import java.sql.JDBCType;
import java.sql.SQLDataException;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Time;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import org.junit.jupiter.api.Test;

/**
 * The reading half of a callable statement, as every driver inherits it: what
 * a value handed back by the driver becomes for each getter, what is refused,
 * and that a name goes through {@code indexOf} and nowhere else.
 */
class OutParametersTest {

    /** What a driver provides: the values by position, the names it knows, and what it was asked. */
    private static final class Driver {
        final Map<Integer, Object> values = new HashMap<>();
        final Map<String, Integer> names = new HashMap<>();
        final List<String> calls = new ArrayList<>();
        boolean lastWasNull;

        OutParameters statement() {
            InvocationHandler handler = (proxy, method, arguments) -> {
                if (method.getName().equals("indexOf") && !names.isEmpty()) {
                    Integer index = names.get((String) arguments[0]);
                    if (index == null) {
                        throw new SQLException("no parameter " + arguments[0]);
                    }
                    return index;
                }
                if (method.isDefault()) {
                    return InvocationHandler.invokeDefault(proxy, method, arguments);
                }
                switch (method.getName()) {
                    case "outValue":
                        Object value = values.get((Integer) arguments[0]);
                        lastWasNull = value == null;
                        return value;
                    case "lastWasNull":
                        return lastWasNull;
                    default:
                        // registerOut and the by-index setters: what the shared code asked for.
                        calls.add(method.getName() + Arrays.toString(arguments));
                        return null;
                }
            };
            return (OutParameters) Proxy.newProxyInstance(OutParameters.class.getClassLoader(),
                    new Class<?>[] {OutParameters.class}, handler);
        }
    }

    private static OutParameters holding(Object value) {
        Driver driver = new Driver();
        driver.values.put(1, value);
        return driver.statement();
    }

    @Test
    void registeringPassesTypeScaleAndTypeNameOn() throws Exception {
        Driver driver = new Driver();
        driver.names.put("total", 3);
        OutParameters call = driver.statement();
        call.registerOutParameter(1, Types.INTEGER);
        call.registerOutParameter(2, Types.NUMERIC, 4);
        call.registerOutParameter(1, Types.STRUCT, "POINT");
        call.registerOutParameter(1, JDBCType.NUMERIC);
        call.registerOutParameter(1, JDBCType.NUMERIC, 2);
        call.registerOutParameter(1, JDBCType.STRUCT, "POINT");
        call.registerOutParameter("total", Types.BIGINT);
        call.registerOutParameter("total", Types.NUMERIC, 1);
        call.registerOutParameter("total", Types.STRUCT, "POINT");
        call.registerOutParameter("total", JDBCType.BIGINT);
        call.registerOutParameter("total", JDBCType.NUMERIC, 1);
        call.registerOutParameter("total", JDBCType.STRUCT, "POINT");
        assertEquals(List.of(
                "registerOut[1, 4, -1, null]", "registerOut[2, 2, 4, null]",
                "registerOut[1, 2002, -1, POINT]", "registerOut[1, 2, -1, null]",
                "registerOut[1, 2, 2, null]", "registerOut[1, 2002, -1, POINT]",
                "registerOut[3, -5, -1, null]", "registerOut[3, 2, 1, null]",
                "registerOut[3, 2002, -1, POINT]", "registerOut[3, -5, -1, null]",
                "registerOut[3, 2, 1, null]", "registerOut[3, 2002, -1, POINT]"), driver.calls);
    }

    @Test
    void aNameIsRefusedByADriverThatDoesNotResolveNames() {
        OutParameters call = new Driver().statement();
        SQLFeatureNotSupportedException refused = assertThrows(
                SQLFeatureNotSupportedException.class, () -> call.getInt("total"));
        assertTrue(refused.getMessage().contains("\"total\""), refused.getMessage());
        assertThrows(SQLFeatureNotSupportedException.class,
                () -> call.registerOutParameter("total", Types.INTEGER));
        assertThrows(SQLFeatureNotSupportedException.class, () -> call.setInt("total", 1));
        assertThrows(SQLFeatureNotSupportedException.class, () -> call.getString("total"));
    }

    @Test
    void aNameReadsThePositionItStandsFor() throws Exception {
        Driver driver = new Driver();
        driver.names.put("total", 2);
        driver.values.put(2, 42L);
        OutParameters call = driver.statement();
        assertEquals(42, call.getInt("total"));
        assertEquals(42L, call.getLong("total"));
        assertEquals((short) 42, call.getShort("total"));
        assertEquals((byte) 42, call.getByte("total"));
        assertEquals(42.0, call.getDouble("total"));
        assertEquals(42.0f, call.getFloat("total"));
        assertEquals("42", call.getString("total"));
        assertEquals(new BigDecimal("42"), call.getBigDecimal("total"));
        assertTrue(call.getBoolean("total"));
        assertThrows(SQLException.class, () -> call.getInt("nothing"));
    }

    @Test
    void integersComeFromNumbersBooleansAndText() throws Exception {
        assertEquals(7L, holding(7).getLong(1));
        assertEquals(7L, holding(new BigDecimal("7.9")).getLong(1));
        assertEquals(1L, holding(Boolean.TRUE).getLong(1));
        assertEquals(0L, holding(Boolean.FALSE).getLong(1));
        assertEquals(42L, holding(" 42 ").getLong(1));
        assertEquals(42L, holding("42.9").getLong(1));
        assertEquals(Long.MIN_VALUE, holding(Long.MIN_VALUE).getLong(1));
        SQLException refused = assertThrows(SQLException.class, () -> holding("forty").getLong(1));
        assertTrue(refused.getMessage().contains("parameter 1"), refused.getMessage());
    }

    @Test
    void nullIsZeroFalseOrNullAndWasNullSaysSo() throws Exception {
        Driver driver = new Driver();
        driver.values.put(2, "x");
        OutParameters call = driver.statement();
        assertEquals(0, call.getInt(1));
        assertTrue(call.wasNull());
        assertEquals(0L, call.getLong(1));
        assertEquals(0.0, call.getDouble(1));
        assertFalse(call.getBoolean(1));
        assertNull(call.getString(1));
        assertNull(call.getBigDecimal(1));
        assertNull(call.getBytes(1));
        assertNull(call.getDate(1));
        assertNull(call.getTime(1));
        assertNull(call.getTimestamp(1));
        assertNull(call.getObject(1));
        assertNull(call.getObject(1, Integer.class));
        assertNull(call.getBlob(1));
        assertNull(call.getClob(1));
        assertEquals("x", call.getString(2));
        assertFalse(call.wasNull());
    }

    /** A number cut to the type's bits is another number: refused, with SQLSTATE 22003. */
    @Test
    void anIntegerThatDoesNotFitIsRefusedNotCut() throws Exception {
        assertEquals(Integer.MAX_VALUE, holding((long) Integer.MAX_VALUE).getInt(1));
        assertEquals(Integer.MIN_VALUE, holding((long) Integer.MIN_VALUE).getInt(1));
        SQLDataException tooLarge = assertThrows(SQLDataException.class,
                () -> holding(5_000_000_000L).getInt(1));
        assertEquals("22003", tooLarge.getSQLState());
        assertFalse(tooLarge.getMessage().contains("5000000000"), "the value is not in the message");
        assertThrows(SQLDataException.class, () -> holding(Integer.MIN_VALUE - 1L).getInt(1));
        assertThrows(SQLDataException.class, () -> holding("5000000000").getInt(1));
        assertThrows(SQLDataException.class, () -> holding(5_000_000_000L)
                .getObject(1, Integer.class));

        assertEquals(Short.MAX_VALUE, holding(32767).getShort(1));
        assertThrows(SQLDataException.class, () -> holding(32768).getShort(1));
        assertThrows(SQLDataException.class, () -> holding(-32769).getShort(1));

        assertEquals((byte) -128, holding(-128).getByte(1));
        // An unsigned TINYINT read as a byte keeps its bits, as it always did.
        assertEquals((byte) 0xff, holding(255).getByte(1));
        assertThrows(SQLDataException.class, () -> holding(256).getByte(1));
        assertThrows(SQLDataException.class, () -> holding(-129).getByte(1));
    }

    @Test
    void booleansComeFromFlagsNumbersAndTheWordsServersWrite() throws Exception {
        assertTrue(holding(Boolean.TRUE).getBoolean(1));
        assertTrue(holding(2).getBoolean(1));
        assertFalse(holding(0).getBoolean(1));
        for (String yes : new String[] {"t", "T", "true", " TRUE ", "y", "yes", "1"}) {
            assertTrue(holding(yes).getBoolean(1), yes);
        }
        for (String no : new String[] {"f", "false", "n", "no", "0", "", "2"}) {
            assertFalse(holding(no).getBoolean(1), no);
        }
    }

    @Test
    void decimalsAndDoubles() throws Exception {
        assertEquals(1.5, holding(1.5f).getDouble(1));
        assertEquals(1.5, holding(" 1.5 ").getDouble(1));
        assertEquals(1.5f, holding("1.5").getFloat(1));
        assertThrows(SQLException.class, () -> holding("one and a half").getDouble(1));
        BigDecimal same = new BigDecimal("12.345");
        assertSame(same, holding(same).getBigDecimal(1));
        assertEquals(new BigDecimal("12.345"), holding(" 12.345 ").getBigDecimal(1));
        assertEquals(new BigDecimal("7"), holding(7L).getBigDecimal(1));
        assertThrows(SQLException.class, () -> holding("twelve").getBigDecimal(1));
    }

    /** {@code getBigDecimal(int, int)}, deprecated since JDBC 2, as it still works. */
    @Test
    @Deprecated
    void aDecimalAskedForWithAScaleIsRoundedHalfUp() throws Exception {
        assertEquals(new BigDecimal("12.35"), holding("12.345").getBigDecimal(1, 2));
        assertEquals(new BigDecimal("12.3450"), holding("12.345").getBigDecimal(1, 4));
        assertNull(holding(null).getBigDecimal(1, 2));
    }

    @Test
    void bytesAreHandedBackAsTheyAreAndNothingElseIsBinary() throws Exception {
        byte[] bytes = {1, 2, 3};
        assertSame(bytes, holding(bytes).getBytes(1));
        SQLException refused = assertThrows(SQLException.class, () -> holding("abc").getBytes(1));
        assertTrue(refused.getMessage().contains("String"), refused.getMessage());
        assertArrayEquals(bytes, holding(bytes).getBlob(1).getBytes(1, 3));
    }

    @Test
    void datesTimesAndTimestampsComeFromEachOtherAndFromText() throws Exception {
        Date date = Date.valueOf("2026-11-13");
        Time time = Time.valueOf("10:11:12");
        Timestamp stamp = Timestamp.valueOf("2026-11-13 10:11:12.5");
        assertSame(date, holding(date).getDate(1));
        assertEquals(date.toString(), holding(stamp).getDate(1).toString());
        assertEquals(date, holding(" 2026-11-13 ").getDate(1));
        assertSame(time, holding(time).getTime(1));
        assertEquals(time.toString(), holding(stamp).getTime(1).toString());
        assertEquals(time, holding("10:11:12").getTime(1));
        assertSame(stamp, holding(stamp).getTimestamp(1));
        assertEquals(new Timestamp(date.getTime()), holding(date).getTimestamp(1));
        assertEquals(stamp, holding("2026-11-13 10:11:12.5").getTimestamp(1));
        Calendar utc = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        assertSame(date, holding(date).getDate(1, utc));
        assertSame(time, holding(time).getTime(1, utc));
        assertSame(stamp, holding(stamp).getTimestamp(1, utc));
    }

    /** Text that is no date is the statement's error - an SQLException, not an unchecked one. */
    @Test
    void textThatIsNoDateTimeOrTimestampIsAnSqlException() {
        SQLException date = assertThrows(SQLException.class,
                () -> holding("13.11.2026").getDate(1));
        assertTrue(date.getMessage().contains("parameter 1"), date.getMessage());
        assertFalse(date.getMessage().contains("13.11.2026"), "the value is not in the message");
        assertThrows(SQLException.class, () -> holding("ten past ten").getTime(1));
        assertThrows(SQLException.class, () -> holding("2026-11-13").getTimestamp(1));
    }

    @Test
    void anObjectIsReadAsTheTypeAskedForOrRefused() throws Exception {
        assertEquals("42", holding(42).getObject(1, String.class));
        assertEquals(42, holding("42").getObject(1, Integer.class));
        assertEquals(42L, holding("42").getObject(1, Long.class));
        assertEquals(4.5, holding("4.5").getObject(1, Double.class));
        assertEquals(Boolean.TRUE, holding("yes").getObject(1, Boolean.class));
        assertEquals(new BigDecimal("4.5"), holding("4.5").getObject(1, BigDecimal.class));
        Timestamp stamp = Timestamp.valueOf("2026-11-13 10:11:12");
        assertSame(stamp, holding(stamp).getObject(1, Timestamp.class));
        assertSame(stamp, holding(stamp).getObject(1));
        assertSame(stamp, holding(stamp).getObject(1, Map.of()));
        SQLException refused = assertThrows(SQLException.class,
                () -> holding("x").getObject(1, java.util.UUID.class));
        assertTrue(refused.getMessage().contains("java.util.UUID"), refused.getMessage());
    }

    @Test
    void textIsALobWhenItIsAskedForAsOne() throws Exception {
        assertEquals("some text", holding("some text").getClob(1).getSubString(1, 9));
        assertEquals("some text", holding("some text").getNClob(1).getSubString(1, 9));
        assertEquals("some text", holding("some text").getNString(1));
    }

    @Test
    void whatNoCallHandsOutIsRefusedNotNull() {
        OutParameters call = holding("x");
        assertThrows(SQLFeatureNotSupportedException.class, () -> call.getRef(1));
        assertThrows(SQLFeatureNotSupportedException.class, () -> call.getRef("p"));
        assertThrows(SQLFeatureNotSupportedException.class, () -> call.getArray(1));
    }

    /** By name with a calendar: the calendar goes on to the setter, not dropped on the way. */
    @Test
    void aSetterByNameKeepsItsCalendar() throws Exception {
        Driver driver = new Driver();
        driver.names.put("at", 2);
        OutParameters call = driver.statement();
        Calendar utc = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        Date date = Date.valueOf("2026-11-13");
        Time time = Time.valueOf("10:11:12");
        Timestamp stamp = Timestamp.valueOf("2026-11-13 10:11:12");
        call.setDate("at", date, utc);
        call.setTime("at", time, utc);
        call.setTimestamp("at", stamp, utc);
        assertEquals(List.of("setDate" + Arrays.toString(new Object[] {2, date, utc}),
                "setTime" + Arrays.toString(new Object[] {2, time, utc}),
                "setTimestamp" + Arrays.toString(new Object[] {2, stamp, utc})), driver.calls);
    }

    @Test
    void settersByNameGoToThePositionTheNameStandsFor() throws Exception {
        Driver driver = new Driver();
        driver.names.put("p", 4);
        OutParameters call = driver.statement();
        call.setNull("p", Types.INTEGER);
        call.setBoolean("p", true);
        call.setInt("p", 7);
        call.setLong("p", 8L);
        call.setString("p", "text");
        call.setNString("p", "text");
        call.setBigDecimal("p", BigDecimal.ONE);
        call.setObject("p", "o");
        call.setObject("p", "o", Types.VARCHAR);
        call.setObject("p", "o", JDBCType.VARCHAR);
        assertEquals(List.of("setNull[4, 4]", "setBoolean[4, true]", "setInt[4, 7]",
                "setLong[4, 8]", "setString[4, text]", "setString[4, text]",
                "setBigDecimal[4, 1]", "setObject[4, o]", "setObject[4, o, 12]",
                "setObject[4, o, 12]"), driver.calls);
    }
}
