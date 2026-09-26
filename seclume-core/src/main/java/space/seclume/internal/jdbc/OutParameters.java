package space.seclume.internal.jdbc;

import java.io.InputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.net.URL;
import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Date;
import java.sql.NClob;
import java.sql.Ref;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLType;
import java.sql.SQLXML;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Map;

/**
 * The reading half of {@code CallableStatement}, written once.
 *
 * <p>Its shape follows {@link ParameterSetters}, and for the same reason:
 * there are some fifty methods here, all of them the same two questions -
 * which parameter, and as what type - and a driver differs only in how it
 * got the value off the wire. Four copies of this would be four places for
 * the same conversion bug.
 *
 * <p>A driver supplies four things: how to register an output, how to hand
 * a value back once the call has run, whether the last one read was NULL,
 * and what a name means. Everything else is here.
 *
 * <p>Only the <b>output</b> half is here. How a driver takes its input
 * values is its own business - three of the four use
 * {@link ParameterSetters} and one writes its setters out - so this
 * deliberately does not prescribe one, and the by-name setters below simply
 * call the by-index ones the driver already has.
 *
 * <p><b>Names are refused by default.</b> Looking a parameter up by name
 * needs the procedure's signature, which means a round trip to the catalog
 * and a cache - real work, and worth doing only where somebody asks for it.
 * A driver that has not done it inherits a refusal that says so, which is
 * better than a guess at position.
 */
public interface OutParameters extends CallableStatement {

    // ---- what a driver has to provide ------------------------------------

    /**
     * Notes that this parameter comes back.
     *
     * @param scale    the decimal places asked for, or -1 for none given
     * @param typeName the named type for a structured output, or null
     */
    void registerOut(int index, int sqlType, int scale, String typeName) throws SQLException;

    /** The value after the call; {@code null} for SQL NULL. */
    Object outValue(int index) throws SQLException;

    /** Whether the value last read through this interface was SQL NULL. */
    boolean lastWasNull();

    /** The position a name stands for, or a refusal. */
    default int indexOf(String parameterName) throws SQLException {
        throw new SQLFeatureNotSupportedException("this driver addresses call parameters by "
                + "position, not by name - use the index of \"" + parameterName + "\"");
    }

    // ---- registering -----------------------------------------------------

    @Override
    default void registerOutParameter(int index, int sqlType) throws SQLException {
        registerOut(index, sqlType, -1, null);
    }

    @Override
    default void registerOutParameter(int index, int sqlType, int scale) throws SQLException {
        registerOut(index, sqlType, scale, null);
    }

    @Override
    default void registerOutParameter(int index, int sqlType, String typeName)
            throws SQLException {
        registerOut(index, sqlType, -1, typeName);
    }

    @Override
    default void registerOutParameter(String name, int sqlType) throws SQLException {
        registerOut(indexOf(name), sqlType, -1, null);
    }

    @Override
    default void registerOutParameter(String name, int sqlType, int scale) throws SQLException {
        registerOut(indexOf(name), sqlType, scale, null);
    }

    @Override
    default void registerOutParameter(String name, int sqlType, String typeName)
            throws SQLException {
        registerOut(indexOf(name), sqlType, -1, typeName);
    }

    @Override
    default void registerOutParameter(int index, SQLType sqlType) throws SQLException {
        registerOut(index, sqlType.getVendorTypeNumber(), -1, null);
    }

    @Override
    default void registerOutParameter(int index, SQLType sqlType, int scale) throws SQLException {
        registerOut(index, sqlType.getVendorTypeNumber(), scale, null);
    }

    @Override
    default void registerOutParameter(int index, SQLType sqlType, String typeName)
            throws SQLException {
        registerOut(index, sqlType.getVendorTypeNumber(), -1, typeName);
    }

    @Override
    default void registerOutParameter(String name, SQLType sqlType) throws SQLException {
        registerOut(indexOf(name), sqlType.getVendorTypeNumber(), -1, null);
    }

    @Override
    default void registerOutParameter(String name, SQLType sqlType, int scale)
            throws SQLException {
        registerOut(indexOf(name), sqlType.getVendorTypeNumber(), scale, null);
    }

    @Override
    default void registerOutParameter(String name, SQLType sqlType, String typeName)
            throws SQLException {
        registerOut(indexOf(name), sqlType.getVendorTypeNumber(), -1, typeName);
    }

    @Override
    default boolean wasNull() throws SQLException {
        return lastWasNull();
    }

    // ---- reading, by index -----------------------------------------------

    @Override
    default String getString(int index) throws SQLException {
        Object value = outValue(index);
        return value == null ? null : value.toString();
    }

    @Override
    default boolean getBoolean(int index) throws SQLException {
        Object value = outValue(index);
        if (value == null) {
            return false;
        }
        if (value instanceof Boolean flag) {
            return flag;
        }
        if (value instanceof Number number) {
            return number.longValue() != 0;
        }
        String text = value.toString().trim();
        return text.equalsIgnoreCase("t") || text.equalsIgnoreCase("true")
                || text.equalsIgnoreCase("y") || text.equalsIgnoreCase("yes")
                || text.equals("1");
    }

    @Override
    default byte getByte(int index) throws SQLException {
        return (byte) getLong(index);
    }

    @Override
    default short getShort(int index) throws SQLException {
        return (short) getLong(index);
    }

    @Override
    default int getInt(int index) throws SQLException {
        return (int) getLong(index);
    }

    @Override
    default long getLong(int index) throws SQLException {
        Object value = outValue(index);
        if (value == null) {
            return 0;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof Boolean flag) {
            return flag ? 1 : 0;
        }
        return parseLong(value.toString().trim(), index);
    }

    @Override
    default float getFloat(int index) throws SQLException {
        return (float) getDouble(index);
    }

    @Override
    default double getDouble(int index) throws SQLException {
        Object value = outValue(index);
        if (value == null) {
            return 0;
        }
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        return parseDouble(value.toString().trim(), index);
    }

    @Override
    default BigDecimal getBigDecimal(int index) throws SQLException {
        Object value = outValue(index);
        if (value == null) {
            return null;
        }
        if (value instanceof BigDecimal decimal) {
            return decimal;
        }
        try {
            return new BigDecimal(value.toString().trim());
        } catch (NumberFormatException e) {
            throw new SQLException("parameter " + index + " is not a number: " + value, e);
        }
    }

    @Override
    @Deprecated
    default BigDecimal getBigDecimal(int index, int scale) throws SQLException {
        BigDecimal value = getBigDecimal(index);
        return value == null ? null : value.setScale(scale, java.math.RoundingMode.HALF_UP);
    }

    @Override
    default byte[] getBytes(int index) throws SQLException {
        Object value = outValue(index);
        if (value == null) {
            return null;
        }
        if (value instanceof byte[] bytes) {
            return bytes;
        }
        throw new SQLException("parameter " + index + " is not binary but a "
                + value.getClass().getSimpleName());
    }

    @Override
    default Date getDate(int index) throws SQLException {
        Object value = outValue(index);
        if (value == null) {
            return null;
        }
        if (value instanceof Date date) {
            return date;
        }
        if (value instanceof Timestamp stamp) {
            return new Date(stamp.getTime());
        }
        return Date.valueOf(value.toString().trim());
    }

    @Override
    default Time getTime(int index) throws SQLException {
        Object value = outValue(index);
        if (value == null) {
            return null;
        }
        if (value instanceof Time time) {
            return time;
        }
        if (value instanceof Timestamp stamp) {
            return new Time(stamp.getTime());
        }
        return Time.valueOf(value.toString().trim());
    }

    @Override
    default Timestamp getTimestamp(int index) throws SQLException {
        Object value = outValue(index);
        if (value == null) {
            return null;
        }
        if (value instanceof Timestamp stamp) {
            return stamp;
        }
        if (value instanceof Date date) {
            return new Timestamp(date.getTime());
        }
        return Timestamp.valueOf(value.toString().trim());
    }

    @Override
    default Object getObject(int index) throws SQLException {
        return outValue(index);
    }

    @Override
    default <T> T getObject(int index, Class<T> type) throws SQLException {
        Object value = outValue(index);
        if (value == null) {
            return null;
        }
        if (type.isInstance(value)) {
            return type.cast(value);
        }
        if (type == String.class) {
            return type.cast(getString(index));
        }
        if (type == Integer.class) {
            return type.cast(getInt(index));
        }
        if (type == Long.class) {
            return type.cast(getLong(index));
        }
        if (type == Double.class) {
            return type.cast(getDouble(index));
        }
        if (type == Boolean.class) {
            return type.cast(getBoolean(index));
        }
        if (type == BigDecimal.class) {
            return type.cast(getBigDecimal(index));
        }
        throw new SQLException("parameter " + index + " is a "
                + value.getClass().getSimpleName() + " and cannot be read as a " + type.getName());
    }

    @Override
    default Date getDate(int index, Calendar calendar) throws SQLException {
        return getDate(index);
    }

    @Override
    default Time getTime(int index, Calendar calendar) throws SQLException {
        return getTime(index);
    }

    @Override
    default Timestamp getTimestamp(int index, Calendar calendar) throws SQLException {
        return getTimestamp(index);
    }

    @Override
    default String getNString(int index) throws SQLException {
        return getString(index);
    }

    @Override
    default Object getObject(int index, Map<String, Class<?>> map) throws SQLException {
        return outValue(index);
    }

    // ---- reading, by name ------------------------------------------------

    @Override
    default String getString(String name) throws SQLException {
        return getString(indexOf(name));
    }

    @Override
    default boolean getBoolean(String name) throws SQLException {
        return getBoolean(indexOf(name));
    }

    @Override
    default byte getByte(String name) throws SQLException {
        return getByte(indexOf(name));
    }

    @Override
    default short getShort(String name) throws SQLException {
        return getShort(indexOf(name));
    }

    @Override
    default int getInt(String name) throws SQLException {
        return getInt(indexOf(name));
    }

    @Override
    default long getLong(String name) throws SQLException {
        return getLong(indexOf(name));
    }

    @Override
    default float getFloat(String name) throws SQLException {
        return getFloat(indexOf(name));
    }

    @Override
    default double getDouble(String name) throws SQLException {
        return getDouble(indexOf(name));
    }

    @Override
    default BigDecimal getBigDecimal(String name) throws SQLException {
        return getBigDecimal(indexOf(name));
    }

    @Override
    default byte[] getBytes(String name) throws SQLException {
        return getBytes(indexOf(name));
    }

    @Override
    default Date getDate(String name) throws SQLException {
        return getDate(indexOf(name));
    }

    @Override
    default Time getTime(String name) throws SQLException {
        return getTime(indexOf(name));
    }

    @Override
    default Timestamp getTimestamp(String name) throws SQLException {
        return getTimestamp(indexOf(name));
    }

    @Override
    default Object getObject(String name) throws SQLException {
        return getObject(indexOf(name));
    }

    @Override
    default <T> T getObject(String name, Class<T> type) throws SQLException {
        return getObject(indexOf(name), type);
    }

    @Override
    default Object getObject(String name, Map<String, Class<?>> map) throws SQLException {
        return getObject(indexOf(name));
    }

    @Override
    default Date getDate(String name, Calendar calendar) throws SQLException {
        return getDate(indexOf(name));
    }

    @Override
    default Time getTime(String name, Calendar calendar) throws SQLException {
        return getTime(indexOf(name));
    }

    @Override
    default Timestamp getTimestamp(String name, Calendar calendar) throws SQLException {
        return getTimestamp(indexOf(name));
    }

    @Override
    default String getNString(String name) throws SQLException {
        return getString(indexOf(name));
    }

    @Override
    default URL getURL(String name) throws SQLException {
        return getURL(indexOf(name));
    }

    // ---- setting, by name ------------------------------------------------
    //
    // The same values a PreparedStatement takes, addressed by name. Each
    // goes through indexOf, so a driver that cannot resolve names refuses
    // these in one place rather than in thirty.

    @Override
    default void setNull(String name, int sqlType) throws SQLException {
        setNull(indexOf(name), sqlType);
    }

    @Override
    default void setNull(String name, int sqlType, String typeName) throws SQLException {
        setNull(indexOf(name), sqlType, typeName);
    }

    @Override
    default void setBoolean(String name, boolean value) throws SQLException {
        setBoolean(indexOf(name), value);
    }

    @Override
    default void setByte(String name, byte value) throws SQLException {
        setByte(indexOf(name), value);
    }

    @Override
    default void setShort(String name, short value) throws SQLException {
        setShort(indexOf(name), value);
    }

    @Override
    default void setInt(String name, int value) throws SQLException {
        setInt(indexOf(name), value);
    }

    @Override
    default void setLong(String name, long value) throws SQLException {
        setLong(indexOf(name), value);
    }

    @Override
    default void setFloat(String name, float value) throws SQLException {
        setFloat(indexOf(name), value);
    }

    @Override
    default void setDouble(String name, double value) throws SQLException {
        setDouble(indexOf(name), value);
    }

    @Override
    default void setBigDecimal(String name, BigDecimal value) throws SQLException {
        setBigDecimal(indexOf(name), value);
    }

    @Override
    default void setString(String name, String value) throws SQLException {
        setString(indexOf(name), value);
    }

    @Override
    default void setNString(String name, String value) throws SQLException {
        setString(indexOf(name), value);
    }

    @Override
    default void setBytes(String name, byte[] value) throws SQLException {
        setBytes(indexOf(name), value);
    }

    @Override
    default void setDate(String name, Date value) throws SQLException {
        setDate(indexOf(name), value);
    }

    @Override
    default void setTime(String name, Time value) throws SQLException {
        setTime(indexOf(name), value);
    }

    @Override
    default void setTimestamp(String name, Timestamp value) throws SQLException {
        setTimestamp(indexOf(name), value);
    }

    @Override
    default void setDate(String name, Date value, Calendar calendar) throws SQLException {
        setDate(indexOf(name), value);
    }

    @Override
    default void setTime(String name, Time value, Calendar calendar) throws SQLException {
        setTime(indexOf(name), value);
    }

    @Override
    default void setTimestamp(String name, Timestamp value, Calendar calendar)
            throws SQLException {
        setTimestamp(indexOf(name), value);
    }

    @Override
    default void setObject(String name, Object value) throws SQLException {
        setObject(indexOf(name), value);
    }

    @Override
    default void setObject(String name, Object value, int targetSqlType) throws SQLException {
        setObject(indexOf(name), value, targetSqlType);
    }

    @Override
    default void setObject(String name, Object value, int targetSqlType, int scale)
            throws SQLException {
        setObject(indexOf(name), value, targetSqlType, scale);
    }

    @Override
    default void setObject(String name, Object value, java.sql.SQLType targetSqlType)
            throws SQLException {
        setObject(indexOf(name), value, ParameterSetters.typeNumber(targetSqlType));
    }

    @Override
    default void setObject(String name, Object value, java.sql.SQLType targetSqlType,
                           int scaleOrLength) throws SQLException {
        setObject(indexOf(name), value, ParameterSetters.typeNumber(targetSqlType),
                scaleOrLength);
    }

    @Override
    default void setURL(String name, URL value) throws SQLException {
        setURL(indexOf(name), value);
    }

    @Override
    default void setAsciiStream(String name, InputStream stream) throws SQLException {
        setAsciiStream(indexOf(name), stream);
    }

    @Override
    default void setAsciiStream(String name, InputStream stream, int length) throws SQLException {
        setAsciiStream(indexOf(name), stream, length);
    }

    @Override
    default void setAsciiStream(String name, InputStream stream, long length)
            throws SQLException {
        setAsciiStream(indexOf(name), stream, length);
    }

    @Override
    default void setBinaryStream(String name, InputStream stream) throws SQLException {
        setBinaryStream(indexOf(name), stream);
    }

    @Override
    default void setBinaryStream(String name, InputStream stream, int length)
            throws SQLException {
        setBinaryStream(indexOf(name), stream, length);
    }

    @Override
    default void setBinaryStream(String name, InputStream stream, long length)
            throws SQLException {
        setBinaryStream(indexOf(name), stream, length);
    }

    @Override
    default void setCharacterStream(String name, Reader reader) throws SQLException {
        setCharacterStream(indexOf(name), reader);
    }

    @Override
    default void setCharacterStream(String name, Reader reader, int length) throws SQLException {
        setCharacterStream(indexOf(name), reader, length);
    }

    @Override
    default void setCharacterStream(String name, Reader reader, long length)
            throws SQLException {
        setCharacterStream(indexOf(name), reader, length);
    }

    @Override
    default void setNCharacterStream(String name, Reader reader) throws SQLException {
        setCharacterStream(indexOf(name), reader);
    }

    @Override
    default void setNCharacterStream(String name, Reader reader, long length)
            throws SQLException {
        setCharacterStream(indexOf(name), reader, length);
    }

    @Override
    default void setBlob(String name, Blob value) throws SQLException {
        setBlob(indexOf(name), value);
    }

    @Override
    default void setBlob(String name, InputStream stream) throws SQLException {
        setBlob(indexOf(name), stream);
    }

    @Override
    default void setBlob(String name, InputStream stream, long length) throws SQLException {
        setBlob(indexOf(name), stream, length);
    }

    @Override
    default void setClob(String name, Clob value) throws SQLException {
        setClob(indexOf(name), value);
    }

    @Override
    default void setClob(String name, Reader reader) throws SQLException {
        setClob(indexOf(name), reader);
    }

    @Override
    default void setClob(String name, Reader reader, long length) throws SQLException {
        setClob(indexOf(name), reader, length);
    }

    @Override
    default void setNClob(String name, NClob value) throws SQLException {
        setNClob(indexOf(name), value);
    }

    @Override
    default void setNClob(String name, Reader reader) throws SQLException {
        setClob(indexOf(name), reader);
    }

    @Override
    default void setNClob(String name, Reader reader, long length) throws SQLException {
        setClob(indexOf(name), reader, length);
    }

    @Override
    default void setRowId(String name, RowId value) throws SQLException {
        setRowId(indexOf(name), value);
    }

    @Override
    default void setSQLXML(String name, SQLXML value) throws SQLException {
        setSQLXML(indexOf(name), value);
    }

    // ---- the ones nothing here hands out ---------------------------------
    //
    // Refused rather than returned empty: a caller that asked for a REF or an
    // ARRAY wants that object, and null would be read as "the procedure
    // returned nothing".

    @Override
    default Ref getRef(int index) throws SQLException {
        throw unsupported("REF");
    }

    @Override
    default Ref getRef(String name) throws SQLException {
        throw unsupported("REF");
    }

    @Override
    default Blob getBlob(int index) throws SQLException {
        Object value = outValue(index);
        if (value == null || value instanceof Blob) {
            return (Blob) value;
        }
        return Lobs.binary(getBytes(index));
    }

    @Override
    default Blob getBlob(String name) throws SQLException {
        return getBlob(indexOf(name));
    }

    @Override
    default Clob getClob(int index) throws SQLException {
        return getNClob(index);
    }

    @Override
    default Clob getClob(String name) throws SQLException {
        return getClob(indexOf(name));
    }

    /**
     * The OUT value as a LOB. The value is already here - an OUT parameter
     * comes back whole with the call's answer - so this is the text or the
     * bytes in a LOB's clothing, which is what the vendors hand back for a
     * {@code VARCHAR} or {@code TEXT} read this way; a driver whose value is
     * a real LOB returns that.
     */
    @Override
    default NClob getNClob(int index) throws SQLException {
        Object value = outValue(index);
        if (value == null || value instanceof NClob) {
            return (NClob) value;
        }
        if (value instanceof Clob clob) {
            return Lobs.text(clob.getSubString(1, (int) clob.length()));
        }
        return Lobs.text(getString(index));
    }

    @Override
    default NClob getNClob(String name) throws SQLException {
        return getNClob(indexOf(name));
    }

    @Override
    default Array getArray(int index) throws SQLException {
        throw unsupported("ARRAY");
    }

    @Override
    default Array getArray(String name) throws SQLException {
        throw unsupported("ARRAY");
    }

    @Override
    default URL getURL(int index) throws SQLException {
        String text = getString(index);
        if (text == null) {
            return null;
        }
        try {
            return java.net.URI.create(text).toURL();
        } catch (IllegalArgumentException | java.net.MalformedURLException notAUrl) {
            throw new SQLException("OUT parameter " + index + " is not a URL", "22018",
                    notAUrl);
        }
    }

    /** A row address from an OUT parameter, in the form the server gave it. */
    @Override
    default RowId getRowId(int index) throws SQLException {
        Object value = outValue(index);
        if (value == null || value instanceof RowId) {
            return (RowId) value;
        }
        return new OpaqueRowId(getString(index));
    }

    @Override
    default RowId getRowId(String name) throws SQLException {
        return getRowId(indexOf(name));
    }

    @Override
    default SQLXML getSQLXML(int index) throws SQLException {
        String text = getString(index);
        return text == null ? null : new XmlValue(text);
    }

    @Override
    default SQLXML getSQLXML(String name) throws SQLException {
        return getSQLXML(indexOf(name));
    }

    @Override
    default Reader getCharacterStream(int index) throws SQLException {
        Object value = outValue(index);
        if (value instanceof Clob clob) {
            return clob.getCharacterStream();
        }
        String text = getString(index);
        return text == null ? null : new java.io.StringReader(text);
    }

    @Override
    default Reader getCharacterStream(String name) throws SQLException {
        return getCharacterStream(indexOf(name));
    }

    @Override
    default Reader getNCharacterStream(int index) throws SQLException {
        return getCharacterStream(index);
    }

    @Override
    default Reader getNCharacterStream(String name) throws SQLException {
        return getNCharacterStream(indexOf(name));
    }

    private static SQLFeatureNotSupportedException unsupported(String what) {
        return new SQLFeatureNotSupportedException("seclume does not hand " + what
                + " out of a call - read it as a value of its own, or select it back");
    }

    private static long parseLong(String text, int index) throws SQLException {
        try {
            return Long.parseLong(text);
        } catch (NumberFormatException e) {
            try {
                return new BigDecimal(text).longValue();
            } catch (NumberFormatException another) {
                throw new SQLException("parameter " + index + " is not a number: " + text, e);
            }
        }
    }

    private static double parseDouble(String text, int index) throws SQLException {
        try {
            return Double.parseDouble(text);
        } catch (NumberFormatException e) {
            throw new SQLException("parameter " + index + " is not a number: " + text, e);
        }
    }
}
