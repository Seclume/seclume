package space.seclume.internal.jdbc;

import java.io.InputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.net.URL;
import java.sql.Array;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Date;
import java.sql.NClob;
import java.sql.PreparedStatement;
import java.sql.Ref;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLXML;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * The {@code set...} methods of {@code PreparedStatement}, written once.
 *
 * <p>There are over forty of them, and in a driver of this shape they all do
 * the same thing: remember the value under an index. What becomes of it on the
 * wire is decided by the driver when it writes the packet, not here.
 *
 * <p>Why an interface and not a superclass: a {@code PreparedStatement} is
 * always also the {@code Statement} of its driver, and Java allows only one
 * superclass. Default methods can be both.
 */
public interface ParameterSetters extends PreparedStatement {

    /**
     * Remembers the value under the one-based index.
     *
     * <p>{@code null} stands for SQL NULL. The driver decides how it puts the
     * type on the wire.
     */
    void setParameter(int index, Object value) throws SQLException;

    @Override
    default void setNull(int index, int sqlType) throws SQLException {
        setParameter(index, null);
    }

    @Override
    default void setNull(int index, int sqlType, String typeName) throws SQLException {
        setParameter(index, null);
    }

    @Override
    default void setBoolean(int index, boolean value) throws SQLException {
        setParameter(index, value);
    }

    @Override
    default void setByte(int index, byte value) throws SQLException {
        setParameter(index, (short) value);
    }

    @Override
    default void setShort(int index, short value) throws SQLException {
        setParameter(index, value);
    }

    @Override
    default void setInt(int index, int value) throws SQLException {
        setParameter(index, value);
    }

    @Override
    default void setLong(int index, long value) throws SQLException {
        setParameter(index, value);
    }

    @Override
    default void setFloat(int index, float value) throws SQLException {
        setParameter(index, value);
    }

    @Override
    default void setDouble(int index, double value) throws SQLException {
        setParameter(index, value);
    }

    @Override
    default void setBigDecimal(int index, BigDecimal value) throws SQLException {
        setParameter(index, value);
    }

    @Override
    default void setString(int index, String value) throws SQLException {
        setParameter(index, value);
    }

    @Override
    default void setBytes(int index, byte[] value) throws SQLException {
        setParameter(index, value);
    }

    @Override
    default void setDate(int index, Date value) throws SQLException {
        setParameter(index, value);
    }

    @Override
    default void setTime(int index, Time value) throws SQLException {
        setParameter(index, value);
    }

    @Override
    default void setTimestamp(int index, Timestamp value) throws SQLException {
        setParameter(index, value);
    }

    /**
     * A date in a given calendar's time zone.
     *
     * <p>These three used to refuse any calendar but the JVM's, which sounded
     * careful and was wrong: it is <b>the</b> way Hibernate writes an
     * {@code Instant} or an {@code OffsetDateTime} - it hands the driver a
     * {@code Timestamp} and a calendar in UTC and expects the fields to be
     * shifted into that zone. Refusing meant that an entity with an
     * {@code Instant} in it could not be saved at all.
     *
     * <p>The shift is the whole of it: the value names a point on the time
     * line, the column has no zone, so what is written are the wall-clock
     * fields that point has <b>in the calendar's zone</b>. Reading does the
     * same in reverse - see {@code ReadOnlyResultSet}.
     */
    @Override
    default void setDate(int index, Date value, Calendar calendar) throws SQLException {
        if (value == null || isDefaultCalendar(calendar)) {
            setParameter(index, value);
            return;
        }
        setParameter(index, java.time.LocalDateTime.ofInstant(
                java.time.Instant.ofEpochMilli(value.getTime()),
                calendar.getTimeZone().toZoneId()).toLocalDate());
    }

    @Override
    default void setTime(int index, Time value, Calendar calendar) throws SQLException {
        if (value == null || isDefaultCalendar(calendar)) {
            setParameter(index, value);
            return;
        }
        setParameter(index, java.time.LocalDateTime.ofInstant(
                java.time.Instant.ofEpochMilli(value.getTime()),
                calendar.getTimeZone().toZoneId()).toLocalTime());
    }

    @Override
    default void setTimestamp(int index, Timestamp value, Calendar calendar) throws SQLException {
        if (value == null || isDefaultCalendar(calendar)) {
            setParameter(index, value);
            return;
        }
        // With the offset, not as bare fields: a column that has a zone -
        // Oracle's "timestamp with time zone", PostgreSQL's timestamptz -
        // would otherwise read them in the session's zone and move the value
        // by the machine's offset. A column without a zone takes the fields
        // and drops the offset, which is what the calendar asked for.
        setParameter(index, value.toInstant().atZone(calendar.getTimeZone().toZoneId())
                .toOffsetDateTime());
    }

    /** Whether the calendar asks for anything the plain value does not already say. */
    private static boolean isDefaultCalendar(Calendar calendar) {
        return calendar == null || calendar.getTimeZone().equals(TimeZone.getDefault());
    }

    @Override
    default void setObject(int index, Object value) throws SQLException {
        setParameter(index, value);
    }

    @Override
    default void setObject(int index, Object value, int targetSqlType) throws SQLException {
        setParameter(index, value);
    }

    @Override
    default void setObject(int index, Object value, int targetSqlType, int scale)
            throws SQLException {
        setParameter(index, value);
    }

    /** MySQL and PostgreSQL are Unicode throughout; N-text is the same text. */
    @Override
    default void setNString(int index, String value) throws SQLException {
        setParameter(index, value);
    }

    // ---- streams: deliberately not ---------------------------------------

    private static SQLFeatureNotSupportedException streams() {
        return new SQLFeatureNotSupportedException(
                "seclume does not take streams as parameters - read the value yourself "
                + "and pass a String or byte[], so the size stays visible at the call site");
    }

    @Override
    default void setAsciiStream(int index, InputStream stream, int length) throws SQLException {
        throw streams();
    }

    @SuppressWarnings("deprecation")
    @Override
    default void setUnicodeStream(int index, InputStream stream, int length) throws SQLException {
        throw streams();
    }

    @Override
    default void setBinaryStream(int index, InputStream stream, int length) throws SQLException {
        throw streams();
    }

    @Override
    default void setAsciiStream(int index, InputStream stream, long length) throws SQLException {
        throw streams();
    }

    @Override
    default void setBinaryStream(int index, InputStream stream, long length) throws SQLException {
        throw streams();
    }

    @Override
    default void setAsciiStream(int index, InputStream stream) throws SQLException {
        throw streams();
    }

    @Override
    default void setBinaryStream(int index, InputStream stream) throws SQLException {
        throw streams();
    }

    @Override
    default void setCharacterStream(int index, Reader reader, int length) throws SQLException {
        throw streams();
    }

    @Override
    default void setCharacterStream(int index, Reader reader, long length) throws SQLException {
        throw streams();
    }

    @Override
    default void setCharacterStream(int index, Reader reader) throws SQLException {
        throw streams();
    }

    @Override
    default void setNCharacterStream(int index, Reader reader, long length) throws SQLException {
        throw streams();
    }

    @Override
    default void setNCharacterStream(int index, Reader reader) throws SQLException {
        throw streams();
    }

    // ---- types seclume does not send ------------------------------------

    private static SQLFeatureNotSupportedException unsupported(String type) {
        return new SQLFeatureNotSupportedException(
                "seclume does not send " + type + " parameters");
    }

    @Override
    default void setRef(int index, Ref value) throws SQLException {
        throw unsupported("REF");
    }

    @Override
    default void setBlob(int index, Blob value) throws SQLException {
        throw unsupported("BLOB");
    }

    @Override
    default void setBlob(int index, InputStream stream, long length) throws SQLException {
        throw unsupported("BLOB");
    }

    @Override
    default void setBlob(int index, InputStream stream) throws SQLException {
        throw unsupported("BLOB");
    }

    @Override
    default void setClob(int index, Clob value) throws SQLException {
        throw unsupported("CLOB");
    }

    @Override
    default void setClob(int index, Reader reader, long length) throws SQLException {
        throw unsupported("CLOB");
    }

    @Override
    default void setClob(int index, Reader reader) throws SQLException {
        throw unsupported("CLOB");
    }

    @Override
    default void setNClob(int index, NClob value) throws SQLException {
        throw unsupported("NCLOB");
    }

    @Override
    default void setNClob(int index, Reader reader, long length) throws SQLException {
        throw unsupported("NCLOB");
    }

    @Override
    default void setNClob(int index, Reader reader) throws SQLException {
        throw unsupported("NCLOB");
    }

    @Override
    default void setArray(int index, Array value) throws SQLException {
        throw unsupported("ARRAY");
    }

    @Override
    default void setRowId(int index, RowId value) throws SQLException {
        throw unsupported("ROWID");
    }

    @Override
    default void setSQLXML(int index, SQLXML value) throws SQLException {
        throw unsupported("SQLXML");
    }

    @Override
    default void setURL(int index, URL value) throws SQLException {
        throw unsupported("URL");
    }
}
