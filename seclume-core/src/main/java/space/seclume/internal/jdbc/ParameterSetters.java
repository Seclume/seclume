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

    /**
     * JDBC 4.2's form with a {@link java.sql.SQLType}: the same as the one
     * with the type's number. It was left to the interface's default, which
     * refuses - so {@code setObject(1, x, JDBCType.INTEGER)} failed where
     * {@code setObject(1, x, Types.INTEGER)} worked.
     */
    @Override
    default void setObject(int index, Object value, java.sql.SQLType targetSqlType)
            throws SQLException {
        setObject(index, value, typeNumber(targetSqlType));
    }

    @Override
    default void setObject(int index, Object value, java.sql.SQLType targetSqlType,
                           int scaleOrLength) throws SQLException {
        setObject(index, value, typeNumber(targetSqlType), scaleOrLength);
    }

    /** A {@code JDBCType}'s number; another vendor's type has nothing to say here. */
    static int typeNumber(java.sql.SQLType type) throws SQLException {
        Integer number = type == null ? null : type.getVendorTypeNumber();
        if (number == null || !"java.sql".equals(type.getVendor())) {
            throw new java.sql.SQLFeatureNotSupportedException("not a java.sql.JDBCType: " + type);
        }
        return number;
    }

    /** MySQL and PostgreSQL are Unicode throughout; N-text is the same text. */
    @Override
    default void setNString(int index, String value) throws SQLException {
        setParameter(index, value);
    }

    // ---- streams: read to the end, then sent as a value ------------------

    /*
     * A stream is read here and the value sent like any other. Said plainly:
     * the value does pass through memory, so a stream buys convenience, not
     * thrift. It is still the right thing to offer - Hibernate binds a Blob
     * or Clob from its LobHelper with setBinaryStream(index, stream, length),
     * Spring's LobHandler does the same, and refusing them turned working
     * mappings into stack traces. The Oracle driver has done this from the
     * start; the other three now do it the same way.
     *
     * A length that is given is held to: a stream that ends early is an
     * error, not a shorter value. See StreamValues.
     */

    @Override
    default void setAsciiStream(int index, InputStream stream, int length) throws SQLException {
        setAsciiStream(index, stream, (long) length);
    }

    @SuppressWarnings("deprecation")
    @Override
    default void setUnicodeStream(int index, InputStream stream, int length) throws SQLException {
        throw new SQLFeatureNotSupportedException("setUnicodeStream is deprecated since "
                + "JDBC 2.0 - use setCharacterStream");
    }

    @Override
    default void setBinaryStream(int index, InputStream stream, int length) throws SQLException {
        setBinaryStream(index, stream, (long) length);
    }

    @Override
    default void setAsciiStream(int index, InputStream stream, long length) throws SQLException {
        setParameter(index, StreamValues.ascii(stream, length));
    }

    @Override
    default void setBinaryStream(int index, InputStream stream, long length) throws SQLException {
        setParameter(index, StreamValues.bytes(stream, length));
    }

    @Override
    default void setAsciiStream(int index, InputStream stream) throws SQLException {
        setAsciiStream(index, stream, StreamValues.UNKNOWN);
    }

    @Override
    default void setBinaryStream(int index, InputStream stream) throws SQLException {
        setBinaryStream(index, stream, StreamValues.UNKNOWN);
    }

    @Override
    default void setCharacterStream(int index, Reader reader, int length) throws SQLException {
        setCharacterStream(index, reader, (long) length);
    }

    @Override
    default void setCharacterStream(int index, Reader reader, long length) throws SQLException {
        setParameter(index, StreamValues.text(reader, length));
    }

    @Override
    default void setCharacterStream(int index, Reader reader) throws SQLException {
        setCharacterStream(index, reader, StreamValues.UNKNOWN);
    }

    @Override
    default void setNCharacterStream(int index, Reader reader, long length) throws SQLException {
        setCharacterStream(index, reader, length);
    }

    @Override
    default void setNCharacterStream(int index, Reader reader) throws SQLException {
        setCharacterStream(index, reader);
    }

    /*
     * A Blob or Clob is a value that happens to have an interface: read it
     * and send what it holds. This is not a server-side LOB and does not
     * create one - PostgreSQL, where a LOB column is an oid and would need
     * one, keeps its own refusal.
     */

    @Override
    default void setBlob(int index, Blob value) throws SQLException {
        setParameter(index, value == null ? null
                : StreamValues.bytes(value.getBinaryStream(), value.length()));
    }

    @Override
    default void setBlob(int index, InputStream stream, long length) throws SQLException {
        setBinaryStream(index, stream, length);
    }

    @Override
    default void setBlob(int index, InputStream stream) throws SQLException {
        setBinaryStream(index, stream);
    }

    @Override
    default void setClob(int index, Clob value) throws SQLException {
        setParameter(index, value == null ? null
                : StreamValues.text(value.getCharacterStream(), value.length()));
    }

    @Override
    default void setClob(int index, Reader reader, long length) throws SQLException {
        setCharacterStream(index, reader, length);
    }

    @Override
    default void setClob(int index, Reader reader) throws SQLException {
        setCharacterStream(index, reader);
    }

    @Override
    default void setNClob(int index, NClob value) throws SQLException {
        setClob(index, value);
    }

    @Override
    default void setNClob(int index, Reader reader, long length) throws SQLException {
        setCharacterStream(index, reader, length);
    }

    @Override
    default void setNClob(int index, Reader reader) throws SQLException {
        setCharacterStream(index, reader);
    }

    // ---- types seclume does not send ------------------------------------

    private static SQLFeatureNotSupportedException unsupported(String type) {
        return new SQLFeatureNotSupportedException(
                "seclume does not send " + type + " parameters");
    }

    @Override
    default void setRef(int index, Ref value) throws SQLException {
        if (value == null) {
            setNull(index, java.sql.Types.REF);
            return;
        }
        throw unsupported("REF");
    }

    @Override
    default void setArray(int index, Array value) throws SQLException {
        // A null is a null whatever type it would have had - JDBC says so for
        // every setter, and the vendors bind it; only a value needs the type.
        if (value == null) {
            setNull(index, java.sql.Types.ARRAY);
            return;
        }
        throw unsupported("ARRAY");
    }

    @Override
    default void setRowId(int index, RowId value) throws SQLException {
        if (value == null) {
            setNull(index, java.sql.Types.ROWID);
            return;
        }
        throw unsupported("ROWID");
    }

    /** XML travels as its text, which is what every one of the servers parses it from. */
    @Override
    default void setSQLXML(int index, SQLXML value) throws SQLException {
        if (value == null) {
            setNull(index, java.sql.Types.SQLXML);
            return;
        }
        setString(index, value.getString());
    }

    /** A URL is stored as its text; none of the four has a type of its own for it. */
    @Override
    default void setURL(int index, URL value) throws SQLException {
        if (value == null) {
            setNull(index, java.sql.Types.DATALINK);
            return;
        }
        setString(index, value.toString());
    }
}
