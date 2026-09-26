package space.seclume.internal.jdbc;

import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.SQLFeatureNotSupportedException;

/**
 * {@code prepareCall} with SQL that is not a procedure call.
 *
 * <p>JDBC means {@code prepareCall} for stored procedures, and this driver
 * translates {@code {call p(?)}} for each server. But frameworks use it for
 * plain queries too - Liquibase asks for the default schema with
 * {@code prepareCall("select current_schema()")} - and pgjdbc, ojdbc and
 * mssql-jdbc all accept that. Refusing it cost Liquibase its schema: it went on
 * without one, never found its own lock table, and tried to create it a
 * second time.
 *
 * <p>So such text becomes a prepared statement in a callable one's clothes:
 * everything a {@code PreparedStatement} does is delegated, and the one thing
 * only a call has - {@code OUT} parameters - is refused with the reason.
 * Generated from the interface rather than written by hand, so no method can
 * be missing.
 */
public final class QueryAsCallable implements CallableStatement {

    private final PreparedStatement query;

    public QueryAsCallable(PreparedStatement query) {
        this.query = query;
    }

    /** The statement that runs the query - for the driver that made it. */
    public PreparedStatement query() {
        return query;
    }

    private static SQLFeatureNotSupportedException noOutParameters() {
        return new SQLFeatureNotSupportedException("this callable statement is a plain query, "
                + "not a procedure call - it has no OUT parameters to register or read");
    }

    @Override
    public boolean getBoolean(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public boolean getBoolean(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public byte getByte(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public byte getByte(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public short getShort(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public short getShort(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public int getInt(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public int getInt(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public long getLong(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public long getLong(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public float getFloat(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public float getFloat(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public double getDouble(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public double getDouble(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public byte[] getBytes(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public byte[] getBytes(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setBoolean(java.lang.String a0, boolean a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setByte(java.lang.String a0, byte a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setShort(java.lang.String a0, short a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setInt(java.lang.String a0, int a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setLong(java.lang.String a0, long a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setFloat(java.lang.String a0, float a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setDouble(java.lang.String a0, double a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Ref getRef(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Ref getRef(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Array getArray(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Array getArray(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setURL(java.lang.String a0, java.net.URL a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.lang.String getString(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.lang.String getString(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.math.BigDecimal getBigDecimal(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    @Deprecated
    @SuppressWarnings("deprecation")
    public java.math.BigDecimal getBigDecimal(int a0, int a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.math.BigDecimal getBigDecimal(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Time getTime(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Time getTime(java.lang.String a0, java.util.Calendar a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Time getTime(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Time getTime(int a0, java.util.Calendar a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setTime(java.lang.String a0, java.sql.Time a1, java.util.Calendar a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setTime(java.lang.String a0, java.sql.Time a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public <T> T getObject(int a0, java.lang.Class<T> a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.lang.Object getObject(java.lang.String a0, java.util.Map<java.lang.String, java.lang.Class<?>> a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.lang.Object getObject(int a0, java.util.Map<java.lang.String, java.lang.Class<?>> a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.lang.Object getObject(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.lang.Object getObject(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public <T> T getObject(java.lang.String a0, java.lang.Class<T> a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setDate(java.lang.String a0, java.sql.Date a1, java.util.Calendar a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setDate(java.lang.String a0, java.sql.Date a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Date getDate(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Date getDate(int a0, java.util.Calendar a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Date getDate(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Date getDate(java.lang.String a0, java.util.Calendar a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.net.URL getURL(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.net.URL getURL(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Timestamp getTimestamp(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Timestamp getTimestamp(int a0, java.util.Calendar a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Timestamp getTimestamp(java.lang.String a0, java.util.Calendar a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Timestamp getTimestamp(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setObject(java.lang.String a0, java.lang.Object a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setObject(java.lang.String a0, java.lang.Object a1, int a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setObject(java.lang.String a0, java.lang.Object a1, int a2, int a3) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setBinaryStream(java.lang.String a0, java.io.InputStream a1, int a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setBinaryStream(java.lang.String a0, java.io.InputStream a1, long a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setBinaryStream(java.lang.String a0, java.io.InputStream a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setCharacterStream(java.lang.String a0, java.io.Reader a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setCharacterStream(java.lang.String a0, java.io.Reader a1, int a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setCharacterStream(java.lang.String a0, java.io.Reader a1, long a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setBigDecimal(java.lang.String a0, java.math.BigDecimal a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setTimestamp(java.lang.String a0, java.sql.Timestamp a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setTimestamp(java.lang.String a0, java.sql.Timestamp a1, java.util.Calendar a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setAsciiStream(java.lang.String a0, java.io.InputStream a1, long a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setAsciiStream(java.lang.String a0, java.io.InputStream a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setAsciiStream(java.lang.String a0, java.io.InputStream a1, int a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void registerOutParameter(int a0, int a1, java.lang.String a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void registerOutParameter(java.lang.String a0, int a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void registerOutParameter(java.lang.String a0, int a1, int a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void registerOutParameter(java.lang.String a0, int a1, java.lang.String a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void registerOutParameter(int a0, int a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void registerOutParameter(int a0, int a1, int a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public boolean wasNull() throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Blob getBlob(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Blob getBlob(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Clob getClob(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.Clob getClob(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setNull(java.lang.String a0, int a1, java.lang.String a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setNull(java.lang.String a0, int a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setString(java.lang.String a0, java.lang.String a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setBytes(java.lang.String a0, byte[] a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.RowId getRowId(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.RowId getRowId(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setNString(java.lang.String a0, java.lang.String a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setNClob(java.lang.String a0, java.io.Reader a1, long a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setNClob(java.lang.String a0, java.io.Reader a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setNClob(java.lang.String a0, java.sql.NClob a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setRowId(java.lang.String a0, java.sql.RowId a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setClob(java.lang.String a0, java.io.Reader a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setClob(java.lang.String a0, java.io.Reader a1, long a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setClob(java.lang.String a0, java.sql.Clob a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.io.Reader getCharacterStream(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.io.Reader getCharacterStream(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.io.Reader getNCharacterStream(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.io.Reader getNCharacterStream(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setNCharacterStream(java.lang.String a0, java.io.Reader a1, long a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setNCharacterStream(java.lang.String a0, java.io.Reader a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setBlob(java.lang.String a0, java.io.InputStream a1, long a2) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setBlob(java.lang.String a0, java.sql.Blob a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setBlob(java.lang.String a0, java.io.InputStream a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.NClob getNClob(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.NClob getNClob(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.lang.String getNString(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.lang.String getNString(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public void setSQLXML(java.lang.String a0, java.sql.SQLXML a1) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.SQLXML getSQLXML(int a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public java.sql.SQLXML getSQLXML(java.lang.String a0) throws java.sql.SQLException {
        throw noOutParameters();
    }

    @Override
    public boolean execute() throws java.sql.SQLException {
        return query.execute();
    }

    @Override
    public void setBoolean(int a0, boolean a1) throws java.sql.SQLException {
        query.setBoolean(a0, a1);
    }

    @Override
    public void setByte(int a0, byte a1) throws java.sql.SQLException {
        query.setByte(a0, a1);
    }

    @Override
    public void setShort(int a0, short a1) throws java.sql.SQLException {
        query.setShort(a0, a1);
    }

    @Override
    public void setInt(int a0, int a1) throws java.sql.SQLException {
        query.setInt(a0, a1);
    }

    @Override
    public void setLong(int a0, long a1) throws java.sql.SQLException {
        query.setLong(a0, a1);
    }

    @Override
    public void setFloat(int a0, float a1) throws java.sql.SQLException {
        query.setFloat(a0, a1);
    }

    @Override
    public void setDouble(int a0, double a1) throws java.sql.SQLException {
        query.setDouble(a0, a1);
    }

    @Override
    public void setURL(int a0, java.net.URL a1) throws java.sql.SQLException {
        query.setURL(a0, a1);
    }

    @Override
    public void setArray(int a0, java.sql.Array a1) throws java.sql.SQLException {
        query.setArray(a0, a1);
    }

    @Override
    public void setTime(int a0, java.sql.Time a1, java.util.Calendar a2) throws java.sql.SQLException {
        query.setTime(a0, a1, a2);
    }

    @Override
    public void setTime(int a0, java.sql.Time a1) throws java.sql.SQLException {
        query.setTime(a0, a1);
    }

    @Override
    public void setDate(int a0, java.sql.Date a1, java.util.Calendar a2) throws java.sql.SQLException {
        query.setDate(a0, a1, a2);
    }

    @Override
    public void setDate(int a0, java.sql.Date a1) throws java.sql.SQLException {
        query.setDate(a0, a1);
    }

    @Override
    public void setObject(int a0, java.lang.Object a1) throws java.sql.SQLException {
        query.setObject(a0, a1);
    }

    @Override
    public void setObject(int a0, java.lang.Object a1, int a2, int a3) throws java.sql.SQLException {
        query.setObject(a0, a1, a2, a3);
    }

    @Override
    public void setObject(int a0, java.lang.Object a1, int a2) throws java.sql.SQLException {
        query.setObject(a0, a1, a2);
    }

    @Override
    public void setBinaryStream(int a0, java.io.InputStream a1, long a2) throws java.sql.SQLException {
        query.setBinaryStream(a0, a1, a2);
    }

    @Override
    public void setBinaryStream(int a0, java.io.InputStream a1) throws java.sql.SQLException {
        query.setBinaryStream(a0, a1);
    }

    @Override
    public void setBinaryStream(int a0, java.io.InputStream a1, int a2) throws java.sql.SQLException {
        query.setBinaryStream(a0, a1, a2);
    }

    @Override
    public void setCharacterStream(int a0, java.io.Reader a1, long a2) throws java.sql.SQLException {
        query.setCharacterStream(a0, a1, a2);
    }

    @Override
    public void setCharacterStream(int a0, java.io.Reader a1, int a2) throws java.sql.SQLException {
        query.setCharacterStream(a0, a1, a2);
    }

    @Override
    public void setCharacterStream(int a0, java.io.Reader a1) throws java.sql.SQLException {
        query.setCharacterStream(a0, a1);
    }

    @Override
    public void setBigDecimal(int a0, java.math.BigDecimal a1) throws java.sql.SQLException {
        query.setBigDecimal(a0, a1);
    }

    @Override
    public void setTimestamp(int a0, java.sql.Timestamp a1, java.util.Calendar a2) throws java.sql.SQLException {
        query.setTimestamp(a0, a1, a2);
    }

    @Override
    public void setTimestamp(int a0, java.sql.Timestamp a1) throws java.sql.SQLException {
        query.setTimestamp(a0, a1);
    }

    @Override
    public void setAsciiStream(int a0, java.io.InputStream a1) throws java.sql.SQLException {
        query.setAsciiStream(a0, a1);
    }

    @Override
    public void setAsciiStream(int a0, java.io.InputStream a1, long a2) throws java.sql.SQLException {
        query.setAsciiStream(a0, a1, a2);
    }

    @Override
    public void setAsciiStream(int a0, java.io.InputStream a1, int a2) throws java.sql.SQLException {
        query.setAsciiStream(a0, a1, a2);
    }

    @Override
    public void setNull(int a0, int a1, java.lang.String a2) throws java.sql.SQLException {
        query.setNull(a0, a1, a2);
    }

    @Override
    public void setNull(int a0, int a1) throws java.sql.SQLException {
        query.setNull(a0, a1);
    }

    @Override
    public void setString(int a0, java.lang.String a1) throws java.sql.SQLException {
        query.setString(a0, a1);
    }

    @Override
    public void setBytes(int a0, byte[] a1) throws java.sql.SQLException {
        query.setBytes(a0, a1);
    }

    @Override
    public void setNString(int a0, java.lang.String a1) throws java.sql.SQLException {
        query.setNString(a0, a1);
    }

    @Override
    public void setNClob(int a0, java.io.Reader a1) throws java.sql.SQLException {
        query.setNClob(a0, a1);
    }

    @Override
    public void setNClob(int a0, java.io.Reader a1, long a2) throws java.sql.SQLException {
        query.setNClob(a0, a1, a2);
    }

    @Override
    public void setNClob(int a0, java.sql.NClob a1) throws java.sql.SQLException {
        query.setNClob(a0, a1);
    }

    @Override
    public void setRowId(int a0, java.sql.RowId a1) throws java.sql.SQLException {
        query.setRowId(a0, a1);
    }

    @Override
    public void setClob(int a0, java.io.Reader a1, long a2) throws java.sql.SQLException {
        query.setClob(a0, a1, a2);
    }

    @Override
    public void setClob(int a0, java.io.Reader a1) throws java.sql.SQLException {
        query.setClob(a0, a1);
    }

    @Override
    public void setClob(int a0, java.sql.Clob a1) throws java.sql.SQLException {
        query.setClob(a0, a1);
    }

    @Override
    @Deprecated
    @SuppressWarnings("deprecation")
    public void setUnicodeStream(int a0, java.io.InputStream a1, int a2) throws java.sql.SQLException {
        query.setUnicodeStream(a0, a1, a2);
    }

    @Override
    public int executeUpdate() throws java.sql.SQLException {
        return query.executeUpdate();
    }

    @Override
    public java.sql.ResultSetMetaData getMetaData() throws java.sql.SQLException {
        return query.getMetaData();
    }

    @Override
    public java.sql.ResultSet executeQuery() throws java.sql.SQLException {
        return query.executeQuery();
    }

    @Override
    public java.sql.ParameterMetaData getParameterMetaData() throws java.sql.SQLException {
        return query.getParameterMetaData();
    }

    @Override
    public void setNCharacterStream(int a0, java.io.Reader a1) throws java.sql.SQLException {
        query.setNCharacterStream(a0, a1);
    }

    @Override
    public void setNCharacterStream(int a0, java.io.Reader a1, long a2) throws java.sql.SQLException {
        query.setNCharacterStream(a0, a1, a2);
    }

    @Override
    public void clearParameters() throws java.sql.SQLException {
        query.clearParameters();
    }

    @Override
    public void addBatch() throws java.sql.SQLException {
        query.addBatch();
    }

    @Override
    public void setBlob(int a0, java.sql.Blob a1) throws java.sql.SQLException {
        query.setBlob(a0, a1);
    }

    @Override
    public void setBlob(int a0, java.io.InputStream a1) throws java.sql.SQLException {
        query.setBlob(a0, a1);
    }

    @Override
    public void setBlob(int a0, java.io.InputStream a1, long a2) throws java.sql.SQLException {
        query.setBlob(a0, a1, a2);
    }

    @Override
    public void setRef(int a0, java.sql.Ref a1) throws java.sql.SQLException {
        query.setRef(a0, a1);
    }

    @Override
    public void setSQLXML(int a0, java.sql.SQLXML a1) throws java.sql.SQLException {
        query.setSQLXML(a0, a1);
    }

    @Override
    public void cancel() throws java.sql.SQLException {
        query.cancel();
    }

    @Override
    public boolean execute(java.lang.String a0, int a1) throws java.sql.SQLException {
        return query.execute(a0, a1);
    }

    @Override
    public boolean execute(java.lang.String a0, int[] a1) throws java.sql.SQLException {
        return query.execute(a0, a1);
    }

    @Override
    public boolean execute(java.lang.String a0, java.lang.String[] a1) throws java.sql.SQLException {
        return query.execute(a0, a1);
    }

    @Override
    public boolean execute(java.lang.String a0) throws java.sql.SQLException {
        return query.execute(a0);
    }

    @Override
    public void close() throws java.sql.SQLException {
        query.close();
    }

    @Override
    public boolean isClosed() throws java.sql.SQLException {
        return query.isClosed();
    }

    @Override
    public int executeUpdate(java.lang.String a0, int a1) throws java.sql.SQLException {
        return query.executeUpdate(a0, a1);
    }

    @Override
    public int executeUpdate(java.lang.String a0, int[] a1) throws java.sql.SQLException {
        return query.executeUpdate(a0, a1);
    }

    @Override
    public int executeUpdate(java.lang.String a0, java.lang.String[] a1) throws java.sql.SQLException {
        return query.executeUpdate(a0, a1);
    }

    @Override
    public int executeUpdate(java.lang.String a0) throws java.sql.SQLException {
        return query.executeUpdate(a0);
    }

    @Override
    public java.sql.ResultSet executeQuery(java.lang.String a0) throws java.sql.SQLException {
        return query.executeQuery(a0);
    }

    @Override
    public void addBatch(java.lang.String a0) throws java.sql.SQLException {
        query.addBatch(a0);
    }

    @Override
    public int getMaxRows() throws java.sql.SQLException {
        return query.getMaxRows();
    }

    @Override
    public void setMaxRows(int a0) throws java.sql.SQLException {
        query.setMaxRows(a0);
    }

    @Override
    public void clearBatch() throws java.sql.SQLException {
        query.clearBatch();
    }

    @Override
    public boolean isPoolable() throws java.sql.SQLException {
        return query.isPoolable();
    }

    @Override
    public int getResultSetConcurrency() throws java.sql.SQLException {
        return query.getResultSetConcurrency();
    }

    @Override
    public java.sql.SQLWarning getWarnings() throws java.sql.SQLException {
        return query.getWarnings();
    }

    @Override
    public int getQueryTimeout() throws java.sql.SQLException {
        return query.getQueryTimeout();
    }

    @Override
    public int getMaxFieldSize() throws java.sql.SQLException {
        return query.getMaxFieldSize();
    }

    @Override
    public void setFetchDirection(int a0) throws java.sql.SQLException {
        query.setFetchDirection(a0);
    }

    @Override
    public int getFetchDirection() throws java.sql.SQLException {
        return query.getFetchDirection();
    }

    @Override
    public int getResultSetType() throws java.sql.SQLException {
        return query.getResultSetType();
    }

    @Override
    public int[] executeBatch() throws java.sql.SQLException {
        return query.executeBatch();
    }

    @Override
    public java.sql.Connection getConnection() throws java.sql.SQLException {
        return query.getConnection();
    }

    @Override
    public java.sql.ResultSet getGeneratedKeys() throws java.sql.SQLException {
        return query.getGeneratedKeys();
    }

    @Override
    public int getResultSetHoldability() throws java.sql.SQLException {
        return query.getResultSetHoldability();
    }

    @Override
    public void closeOnCompletion() throws java.sql.SQLException {
        query.closeOnCompletion();
    }

    @Override
    public java.sql.ResultSet getResultSet() throws java.sql.SQLException {
        return query.getResultSet();
    }

    @Override
    public void clearWarnings() throws java.sql.SQLException {
        query.clearWarnings();
    }

    @Override
    public void setFetchSize(int a0) throws java.sql.SQLException {
        query.setFetchSize(a0);
    }

    @Override
    public void setMaxFieldSize(int a0) throws java.sql.SQLException {
        query.setMaxFieldSize(a0);
    }

    @Override
    public void setEscapeProcessing(boolean a0) throws java.sql.SQLException {
        query.setEscapeProcessing(a0);
    }

    @Override
    public int getUpdateCount() throws java.sql.SQLException {
        return query.getUpdateCount();
    }

    @Override
    public int getFetchSize() throws java.sql.SQLException {
        return query.getFetchSize();
    }

    @Override
    public boolean getMoreResults() throws java.sql.SQLException {
        return query.getMoreResults();
    }

    @Override
    public boolean getMoreResults(int a0) throws java.sql.SQLException {
        return query.getMoreResults(a0);
    }

    @Override
    public void setPoolable(boolean a0) throws java.sql.SQLException {
        query.setPoolable(a0);
    }

    @Override
    public void setQueryTimeout(int a0) throws java.sql.SQLException {
        query.setQueryTimeout(a0);
    }

    @Override
    public void setCursorName(java.lang.String a0) throws java.sql.SQLException {
        query.setCursorName(a0);
    }

    @Override
    public boolean isCloseOnCompletion() throws java.sql.SQLException {
        return query.isCloseOnCompletion();
    }

    @Override
    public <T> T unwrap(java.lang.Class<T> a0) throws java.sql.SQLException {
        return query.unwrap(a0);
    }

    @Override
    public boolean isWrapperFor(java.lang.Class<?> a0) throws java.sql.SQLException {
        return query.isWrapperFor(a0);
    }
}
