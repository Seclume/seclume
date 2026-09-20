package space.seclume.postgresql.jdbc;

import java.lang.reflect.Array;
import java.math.BigDecimal;
import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Time;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import space.seclume.internal.jdbc.ListResultSet;

/**
 * A PostgreSQL array column as a JDBC {@link java.sql.Array}.
 *
 * <p>The value arrives as the server's text form and is taken apart by
 * {@link PgArrayText}; this class turns the resulting strings into the Java
 * type the element oid calls for, and answers the four questions JDBC asks of
 * an array: what its elements are, what type they have, what that type is
 * called, and the same thing again as a result set.
 *
 * <p>Nothing is decoded until somebody asks. A row with an array column that
 * the application never reads costs one substring and no conversion at all,
 * which matters because arrays are usually the wide column in a row rather
 * than the one being filtered on.
 *
 * <p>Multi-dimensional arrays are returned as nested Java arrays, as JDBC
 * says. A jagged one cannot occur - PostgreSQL rejects it on the way in - so
 * the element type of the inner arrays is the same all the way down.
 *
 * <p>The {@code index}/{@code count} overloads count from <b>1</b>, which is
 * JDBC's rule and, as it happens, PostgreSQL's default lower bound as well. An
 * array declared with another lower bound loses it here; JDBC has nowhere to
 * put it.
 */
final class PgArray implements java.sql.Array {

    private final int elementOid;
    private final String text;
    private List<Object> parsed;
    private boolean freed;

    PgArray(int arrayOid, String text) {
        this.elementOid = PgOids.elementOf(arrayOid);
        this.text = text;
    }

    @Override
    public String getBaseTypeName() {
        return PgOids.typeName(elementOid);
    }

    @Override
    public int getBaseType() {
        return PgOids.sqlType(elementOid);
    }

    @Override
    public Object getArray() throws SQLException {
        List<Object> all = elements();
        return build(all, 0, all.size());
    }

    @Override
    public Object getArray(long index, int count) throws SQLException {
        List<Object> all = elements();
        int from = checkedStart(index, all.size());
        return build(all, from, Math.min(from + Math.max(count, 0), all.size()));
    }

    @Override
    public Object getArray(Map<String, Class<?>> map) throws SQLException {
        return withoutMap(map) ? getArray() : null;
    }

    @Override
    public Object getArray(long index, int count, Map<String, Class<?>> map) throws SQLException {
        return withoutMap(map) ? getArray(index, count) : null;
    }

    @Override
    public ResultSet getResultSet() throws SQLException {
        List<Object> all = elements();
        return resultSet(all, 0, all.size());
    }

    @Override
    public ResultSet getResultSet(long index, int count) throws SQLException {
        List<Object> all = elements();
        int from = checkedStart(index, all.size());
        return resultSet(all, from, Math.min(from + Math.max(count, 0), all.size()));
    }

    @Override
    public ResultSet getResultSet(Map<String, Class<?>> map) throws SQLException {
        return withoutMap(map) ? getResultSet() : null;
    }

    @Override
    public ResultSet getResultSet(long index, int count, Map<String, Class<?>> map)
            throws SQLException {
        return withoutMap(map) ? getResultSet(index, count) : null;
    }

    @Override
    public void free() {
        freed = true;
        parsed = null;
    }

    /** The literal the server sent - which is also what it would accept back. */
    @Override
    public String toString() {
        return text;
    }

    // ---- taking it apart --------------------------------------------------

    private List<Object> elements() throws SQLException {
        if (freed) {
            throw new SQLException("this Array has been freed");
        }
        if (parsed == null) {
            parsed = PgArrayText.parse(text, PgOids.arrayDelimiter(elementOid));
        }
        return parsed;
    }

    /**
     * Builds the Java array for a slice of one level.
     *
     * <p>The component type comes from the element oid rather than from the
     * values, so an array whose elements are all null still comes back as
     * {@code Integer[]} and not as {@code Object[]}. An ORM reads the
     * component type; getting it from the data would make the answer depend on
     * the row.
     */
    private Object build(List<Object> level, int from, int to) throws SQLException {
        boolean nested = false;
        for (int i = from; i < to; i++) {
            if (level.get(i) instanceof List) {
                nested = true;
                break;
            }
        }
        if (nested) {
            Object[] out = new Object[to - from];
            for (int i = from; i < to; i++) {
                @SuppressWarnings("unchecked")
                List<Object> inner = (List<Object>) level.get(i);
                out[i - from] = build(inner, 0, inner.size());
            }
            return out;
        }
        Object out = Array.newInstance(componentType(), to - from);
        for (int i = from; i < to; i++) {
            Array.set(out, i - from, convert((String) level.get(i)));
        }
        return out;
    }

    private ResultSet resultSet(List<Object> level, int from, int to) throws SQLException {
        List<Object[]> rows = new ArrayList<>(to - from);
        for (int i = from; i < to; i++) {
            Object value;
            if (level.get(i) instanceof List<?> inner) {
                @SuppressWarnings("unchecked")
                List<Object> nested = (List<Object>) inner;
                value = build(nested, 0, nested.size());
            } else {
                value = convert((String) level.get(i));
            }
            rows.add(new Object[] {(long) (i + 1), value});
        }
        return new ListResultSet(
                new String[] {"INDEX", "VALUE"},
                new int[] {Types.BIGINT, getBaseType()},
                new String[] {"int8", getBaseTypeName()},
                rows);
    }

    private Class<?> componentType() {
        return switch (elementOid) {
            case PgOids.BOOL -> Boolean.class;
            case PgOids.INT2 -> Short.class;
            case PgOids.INT4, PgOids.OID -> Integer.class;
            case PgOids.INT8 -> Long.class;
            case PgOids.FLOAT4 -> Float.class;
            case PgOids.FLOAT8 -> Double.class;
            case PgOids.NUMERIC -> BigDecimal.class;
            case PgOids.BYTEA -> byte[].class;
            case PgOids.DATE -> Date.class;
            case PgOids.TIME -> Time.class;
            case PgOids.TIMESTAMP, PgOids.TIMESTAMPTZ -> Timestamp.class;
            case PgOids.UUID -> UUID.class;
            default -> String.class;
        };
    }

    /**
     * One element, from its text form to the Java type.
     *
     * <p>The timestamp types go through {@code java.time} rather than through
     * {@code Timestamp.valueOf}, because the latter reads the text in the
     * JVM's default zone and would make the same array come back differently
     * on two machines.
     */
    private Object convert(String value) throws SQLException {
        if (value == null) {
            return null;
        }
        try {
            return switch (elementOid) {
                case PgOids.BOOL -> value.equals("t") || value.equals("true") || value.equals("1");
                case PgOids.INT2 -> Short.valueOf(value);
                case PgOids.INT4, PgOids.OID -> Integer.valueOf(value);
                case PgOids.INT8 -> Long.valueOf(value);
                case PgOids.FLOAT4 -> Float.valueOf(value);
                case PgOids.FLOAT8 -> Double.valueOf(value);
                case PgOids.NUMERIC -> new BigDecimal(value);
                case PgOids.BYTEA -> decodeHex(value);
                case PgOids.DATE -> Date.valueOf(LocalDate.parse(value));
                case PgOids.TIME -> Time.valueOf(LocalTime.parse(value));
                case PgOids.TIMESTAMP -> Timestamp.valueOf(
                        LocalDateTime.parse(value.replace(' ', 'T')));
                case PgOids.TIMESTAMPTZ -> Timestamp.from(
                        OffsetDateTime.parse(withColonInOffset(value.replace(' ', 'T'))).toInstant());
                case PgOids.UUID -> UUID.fromString(value);
                default -> value;
            };
        } catch (RuntimeException notThatType) {
            throw new SQLException("array element is not a " + getBaseTypeName() + ": " + value,
                    "22018", notThatType);
        }
    }

    /**
     * PostgreSQL writes the zone as {@code +02}, and {@code OffsetDateTime}
     * wants {@code +02:00}. Two characters, and without them every
     * {@code timestamptz} array fails to parse.
     */
    private static String withColonInOffset(String value) {
        int sign = Math.max(value.lastIndexOf('+'), value.lastIndexOf('-'));
        if (sign > 10 && value.length() - sign == 3) {
            return value + ":00";
        }
        return value;
    }

    /** {@code bytea} inside an array, in the same {@code \x...} form as outside one. */
    private static byte[] decodeHex(String value) {
        String digits = value.startsWith("\\x") ? value.substring(2) : value;
        byte[] out = new byte[digits.length() / 2]; // seclume-allow: user payload, not a secret
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(digits.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static int checkedStart(long index, int size) throws SQLException {
        if (index < 1 || index > size + 1L) {
            throw new SQLException("array index " + index + " is outside 1.." + size, "2202E");
        }
        return (int) index - 1;
    }

    /**
     * A type map would let a caller say which Java class a SQL type becomes.
     * Nothing here honours one, so being handed a non-empty map is refused
     * rather than silently ignored - ignoring it would return the wrong
     * classes and look like it had worked.
     */
    private boolean withoutMap(Map<String, Class<?>> map) throws SQLException {
        if (map != null && !map.isEmpty()) {
            throw new SQLFeatureNotSupportedException(
                    "seclume does not apply a type map to array elements");
        }
        return true;
    }

}
