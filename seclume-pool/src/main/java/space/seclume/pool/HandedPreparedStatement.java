package space.seclume.pool;

/**
 * A statement as the pool lends it: every call goes to the driver's statement,
 * and {@link #getConnection()} answers the pool's handle. The driver's own
 * connection behind it was what {@code statement.getConnection()} gave: closed
 * there, it closed under the pool; kept, it outlived the borrow and was the
 * next borrower's session.
 *
 * <p>Written out rather than proxied, as {@link CachedPreparedStatement} is and
 * for its reason: javac refuses a missing method. Generated from the
 * interface; {@code DelegationIsCompleteTest} counts it.
 */
final class HandedPreparedStatement implements java.sql.PreparedStatement {

    private final java.sql.PreparedStatement statement;
    private final java.sql.Connection handle;

    HandedPreparedStatement(java.sql.PreparedStatement statement, java.sql.Connection handle) {
        this.statement = statement;
        this.handle = handle;
    }

    /** The driver's statement - for the pool's own bookkeeping. */
    java.sql.PreparedStatement delegate() {
        return statement;
    }

    @Override
    public void addBatch() throws java.sql.SQLException {
        statement.addBatch();
    }

    @Override
    public void addBatch(java.lang.String a0) throws java.sql.SQLException {
        statement.addBatch(a0);
    }

    @Override
    public void cancel() throws java.sql.SQLException {
        statement.cancel();
    }

    @Override
    public void clearBatch() throws java.sql.SQLException {
        statement.clearBatch();
    }

    @Override
    public void clearParameters() throws java.sql.SQLException {
        statement.clearParameters();
    }

    @Override
    public void clearWarnings() throws java.sql.SQLException {
        statement.clearWarnings();
    }

    @Override
    public void close() throws java.sql.SQLException {
        statement.close();
    }

    @Override
    public void closeOnCompletion() throws java.sql.SQLException {
        statement.closeOnCompletion();
    }

    @Override
    public java.lang.String enquoteIdentifier(java.lang.String a0, boolean a1) throws java.sql.SQLException {
        return statement.enquoteIdentifier(a0, a1);
    }

    @Override
    public java.lang.String enquoteLiteral(java.lang.String a0) throws java.sql.SQLException {
        return statement.enquoteLiteral(a0);
    }

    @Override
    public java.lang.String enquoteNCharLiteral(java.lang.String a0) throws java.sql.SQLException {
        return statement.enquoteNCharLiteral(a0);
    }

    @Override
    public boolean execute() throws java.sql.SQLException {
        return statement.execute();
    }

    @Override
    public boolean execute(java.lang.String a0, int[] a1) throws java.sql.SQLException {
        return statement.execute(a0, a1);
    }

    @Override
    public boolean execute(java.lang.String a0, java.lang.String[] a1) throws java.sql.SQLException {
        return statement.execute(a0, a1);
    }

    @Override
    public boolean execute(java.lang.String a0, int a1) throws java.sql.SQLException {
        return statement.execute(a0, a1);
    }

    @Override
    public boolean execute(java.lang.String a0) throws java.sql.SQLException {
        return statement.execute(a0);
    }

    @Override
    public int[] executeBatch() throws java.sql.SQLException {
        return statement.executeBatch();
    }

    @Override
    public long[] executeLargeBatch() throws java.sql.SQLException {
        return statement.executeLargeBatch();
    }

    @Override
    public long executeLargeUpdate() throws java.sql.SQLException {
        return statement.executeLargeUpdate();
    }

    @Override
    public long executeLargeUpdate(java.lang.String a0, int[] a1) throws java.sql.SQLException {
        return statement.executeLargeUpdate(a0, a1);
    }

    @Override
    public long executeLargeUpdate(java.lang.String a0, java.lang.String[] a1) throws java.sql.SQLException {
        return statement.executeLargeUpdate(a0, a1);
    }

    @Override
    public long executeLargeUpdate(java.lang.String a0, int a1) throws java.sql.SQLException {
        return statement.executeLargeUpdate(a0, a1);
    }

    @Override
    public long executeLargeUpdate(java.lang.String a0) throws java.sql.SQLException {
        return statement.executeLargeUpdate(a0);
    }

    @Override
    public java.sql.ResultSet executeQuery() throws java.sql.SQLException {
        return statement.executeQuery();
    }

    @Override
    public java.sql.ResultSet executeQuery(java.lang.String a0) throws java.sql.SQLException {
        return statement.executeQuery(a0);
    }

    @Override
    public int executeUpdate() throws java.sql.SQLException {
        return statement.executeUpdate();
    }

    @Override
    public int executeUpdate(java.lang.String a0, int[] a1) throws java.sql.SQLException {
        return statement.executeUpdate(a0, a1);
    }

    @Override
    public int executeUpdate(java.lang.String a0, java.lang.String[] a1) throws java.sql.SQLException {
        return statement.executeUpdate(a0, a1);
    }

    @Override
    public int executeUpdate(java.lang.String a0, int a1) throws java.sql.SQLException {
        return statement.executeUpdate(a0, a1);
    }

    @Override
    public int executeUpdate(java.lang.String a0) throws java.sql.SQLException {
        return statement.executeUpdate(a0);
    }

    @Override
    public java.sql.Connection getConnection() throws java.sql.SQLException {
        return handle;
    }

    @Override
    public int getFetchDirection() throws java.sql.SQLException {
        return statement.getFetchDirection();
    }

    @Override
    public int getFetchSize() throws java.sql.SQLException {
        return statement.getFetchSize();
    }

    @Override
    public java.sql.ResultSet getGeneratedKeys() throws java.sql.SQLException {
        return statement.getGeneratedKeys();
    }

    @Override
    public long getLargeMaxRows() throws java.sql.SQLException {
        return statement.getLargeMaxRows();
    }

    @Override
    public long getLargeUpdateCount() throws java.sql.SQLException {
        return statement.getLargeUpdateCount();
    }

    @Override
    public int getMaxFieldSize() throws java.sql.SQLException {
        return statement.getMaxFieldSize();
    }

    @Override
    public int getMaxRows() throws java.sql.SQLException {
        return statement.getMaxRows();
    }

    @Override
    public java.sql.ResultSetMetaData getMetaData() throws java.sql.SQLException {
        return statement.getMetaData();
    }

    @Override
    public boolean getMoreResults() throws java.sql.SQLException {
        return statement.getMoreResults();
    }

    @Override
    public boolean getMoreResults(int a0) throws java.sql.SQLException {
        return statement.getMoreResults(a0);
    }

    @Override
    public java.sql.ParameterMetaData getParameterMetaData() throws java.sql.SQLException {
        return statement.getParameterMetaData();
    }

    @Override
    public int getQueryTimeout() throws java.sql.SQLException {
        return statement.getQueryTimeout();
    }

    @Override
    public java.sql.ResultSet getResultSet() throws java.sql.SQLException {
        return statement.getResultSet();
    }

    @Override
    public int getResultSetConcurrency() throws java.sql.SQLException {
        return statement.getResultSetConcurrency();
    }

    @Override
    public int getResultSetHoldability() throws java.sql.SQLException {
        return statement.getResultSetHoldability();
    }

    @Override
    public int getResultSetType() throws java.sql.SQLException {
        return statement.getResultSetType();
    }

    @Override
    public int getUpdateCount() throws java.sql.SQLException {
        return statement.getUpdateCount();
    }

    @Override
    public java.sql.SQLWarning getWarnings() throws java.sql.SQLException {
        return statement.getWarnings();
    }

    @Override
    public boolean isCloseOnCompletion() throws java.sql.SQLException {
        return statement.isCloseOnCompletion();
    }

    @Override
    public boolean isClosed() throws java.sql.SQLException {
        return statement.isClosed();
    }

    @Override
    public boolean isPoolable() throws java.sql.SQLException {
        return statement.isPoolable();
    }

    @Override
    public boolean isSimpleIdentifier(java.lang.String a0) throws java.sql.SQLException {
        return statement.isSimpleIdentifier(a0);
    }

    @Override
    public boolean isWrapperFor(java.lang.Class<?> a0) throws java.sql.SQLException {
        return statement.isWrapperFor(a0);
    }

    @Override
    public void setArray(int a0, java.sql.Array a1) throws java.sql.SQLException {
        statement.setArray(a0, a1);
    }

    @Override
    public void setAsciiStream(int a0, java.io.InputStream a1, int a2) throws java.sql.SQLException {
        statement.setAsciiStream(a0, a1, a2);
    }

    @Override
    public void setAsciiStream(int a0, java.io.InputStream a1, long a2) throws java.sql.SQLException {
        statement.setAsciiStream(a0, a1, a2);
    }

    @Override
    public void setAsciiStream(int a0, java.io.InputStream a1) throws java.sql.SQLException {
        statement.setAsciiStream(a0, a1);
    }

    @Override
    public void setBigDecimal(int a0, java.math.BigDecimal a1) throws java.sql.SQLException {
        statement.setBigDecimal(a0, a1);
    }

    @Override
    public void setBinaryStream(int a0, java.io.InputStream a1, int a2) throws java.sql.SQLException {
        statement.setBinaryStream(a0, a1, a2);
    }

    @Override
    public void setBinaryStream(int a0, java.io.InputStream a1, long a2) throws java.sql.SQLException {
        statement.setBinaryStream(a0, a1, a2);
    }

    @Override
    public void setBinaryStream(int a0, java.io.InputStream a1) throws java.sql.SQLException {
        statement.setBinaryStream(a0, a1);
    }

    @Override
    public void setBlob(int a0, java.io.InputStream a1, long a2) throws java.sql.SQLException {
        statement.setBlob(a0, a1, a2);
    }

    @Override
    public void setBlob(int a0, java.io.InputStream a1) throws java.sql.SQLException {
        statement.setBlob(a0, a1);
    }

    @Override
    public void setBlob(int a0, java.sql.Blob a1) throws java.sql.SQLException {
        statement.setBlob(a0, a1);
    }

    @Override
    public void setBoolean(int a0, boolean a1) throws java.sql.SQLException {
        statement.setBoolean(a0, a1);
    }

    @Override
    public void setByte(int a0, byte a1) throws java.sql.SQLException {
        statement.setByte(a0, a1);
    }

    @Override
    public void setBytes(int a0, byte[] a1) throws java.sql.SQLException {
        statement.setBytes(a0, a1);
    }

    @Override
    public void setCharacterStream(int a0, java.io.Reader a1, int a2) throws java.sql.SQLException {
        statement.setCharacterStream(a0, a1, a2);
    }

    @Override
    public void setCharacterStream(int a0, java.io.Reader a1, long a2) throws java.sql.SQLException {
        statement.setCharacterStream(a0, a1, a2);
    }

    @Override
    public void setCharacterStream(int a0, java.io.Reader a1) throws java.sql.SQLException {
        statement.setCharacterStream(a0, a1);
    }

    @Override
    public void setClob(int a0, java.io.Reader a1, long a2) throws java.sql.SQLException {
        statement.setClob(a0, a1, a2);
    }

    @Override
    public void setClob(int a0, java.io.Reader a1) throws java.sql.SQLException {
        statement.setClob(a0, a1);
    }

    @Override
    public void setClob(int a0, java.sql.Clob a1) throws java.sql.SQLException {
        statement.setClob(a0, a1);
    }

    @Override
    public void setCursorName(java.lang.String a0) throws java.sql.SQLException {
        statement.setCursorName(a0);
    }

    @Override
    public void setDate(int a0, java.sql.Date a1, java.util.Calendar a2) throws java.sql.SQLException {
        statement.setDate(a0, a1, a2);
    }

    @Override
    public void setDate(int a0, java.sql.Date a1) throws java.sql.SQLException {
        statement.setDate(a0, a1);
    }

    @Override
    public void setDouble(int a0, double a1) throws java.sql.SQLException {
        statement.setDouble(a0, a1);
    }

    @Override
    public void setEscapeProcessing(boolean a0) throws java.sql.SQLException {
        statement.setEscapeProcessing(a0);
    }

    @Override
    public void setFetchDirection(int a0) throws java.sql.SQLException {
        statement.setFetchDirection(a0);
    }

    @Override
    public void setFetchSize(int a0) throws java.sql.SQLException {
        statement.setFetchSize(a0);
    }

    @Override
    public void setFloat(int a0, float a1) throws java.sql.SQLException {
        statement.setFloat(a0, a1);
    }

    @Override
    public void setInt(int a0, int a1) throws java.sql.SQLException {
        statement.setInt(a0, a1);
    }

    @Override
    public void setLargeMaxRows(long a0) throws java.sql.SQLException {
        statement.setLargeMaxRows(a0);
    }

    @Override
    public void setLong(int a0, long a1) throws java.sql.SQLException {
        statement.setLong(a0, a1);
    }

    @Override
    public void setMaxFieldSize(int a0) throws java.sql.SQLException {
        statement.setMaxFieldSize(a0);
    }

    @Override
    public void setMaxRows(int a0) throws java.sql.SQLException {
        statement.setMaxRows(a0);
    }

    @Override
    public void setNCharacterStream(int a0, java.io.Reader a1, long a2) throws java.sql.SQLException {
        statement.setNCharacterStream(a0, a1, a2);
    }

    @Override
    public void setNCharacterStream(int a0, java.io.Reader a1) throws java.sql.SQLException {
        statement.setNCharacterStream(a0, a1);
    }

    @Override
    public void setNClob(int a0, java.io.Reader a1, long a2) throws java.sql.SQLException {
        statement.setNClob(a0, a1, a2);
    }

    @Override
    public void setNClob(int a0, java.io.Reader a1) throws java.sql.SQLException {
        statement.setNClob(a0, a1);
    }

    @Override
    public void setNClob(int a0, java.sql.NClob a1) throws java.sql.SQLException {
        statement.setNClob(a0, a1);
    }

    @Override
    public void setNString(int a0, java.lang.String a1) throws java.sql.SQLException {
        statement.setNString(a0, a1);
    }

    @Override
    public void setNull(int a0, int a1, java.lang.String a2) throws java.sql.SQLException {
        statement.setNull(a0, a1, a2);
    }

    @Override
    public void setNull(int a0, int a1) throws java.sql.SQLException {
        statement.setNull(a0, a1);
    }

    @Override
    public void setObject(int a0, java.lang.Object a1, int a2, int a3) throws java.sql.SQLException {
        statement.setObject(a0, a1, a2, a3);
    }

    @Override
    public void setObject(int a0, java.lang.Object a1, int a2) throws java.sql.SQLException {
        statement.setObject(a0, a1, a2);
    }

    @Override
    public void setObject(int a0, java.lang.Object a1, java.sql.SQLType a2, int a3) throws java.sql.SQLException {
        statement.setObject(a0, a1, a2, a3);
    }

    @Override
    public void setObject(int a0, java.lang.Object a1, java.sql.SQLType a2) throws java.sql.SQLException {
        statement.setObject(a0, a1, a2);
    }

    @Override
    public void setObject(int a0, java.lang.Object a1) throws java.sql.SQLException {
        statement.setObject(a0, a1);
    }

    @Override
    public void setPoolable(boolean a0) throws java.sql.SQLException {
        statement.setPoolable(a0);
    }

    @Override
    public void setQueryTimeout(int a0) throws java.sql.SQLException {
        statement.setQueryTimeout(a0);
    }

    @Override
    public void setRef(int a0, java.sql.Ref a1) throws java.sql.SQLException {
        statement.setRef(a0, a1);
    }

    @Override
    public void setRowId(int a0, java.sql.RowId a1) throws java.sql.SQLException {
        statement.setRowId(a0, a1);
    }

    @Override
    public void setSQLXML(int a0, java.sql.SQLXML a1) throws java.sql.SQLException {
        statement.setSQLXML(a0, a1);
    }

    @Override
    public void setShort(int a0, short a1) throws java.sql.SQLException {
        statement.setShort(a0, a1);
    }

    @Override
    public void setString(int a0, java.lang.String a1) throws java.sql.SQLException {
        statement.setString(a0, a1);
    }

    @Override
    public void setTime(int a0, java.sql.Time a1, java.util.Calendar a2) throws java.sql.SQLException {
        statement.setTime(a0, a1, a2);
    }

    @Override
    public void setTime(int a0, java.sql.Time a1) throws java.sql.SQLException {
        statement.setTime(a0, a1);
    }

    @Override
    public void setTimestamp(int a0, java.sql.Timestamp a1, java.util.Calendar a2) throws java.sql.SQLException {
        statement.setTimestamp(a0, a1, a2);
    }

    @Override
    public void setTimestamp(int a0, java.sql.Timestamp a1) throws java.sql.SQLException {
        statement.setTimestamp(a0, a1);
    }

    @Override
    public void setURL(int a0, java.net.URL a1) throws java.sql.SQLException {
        statement.setURL(a0, a1);
    }

    @Override
    @Deprecated
    @SuppressWarnings("deprecation")
    public void setUnicodeStream(int a0, java.io.InputStream a1, int a2) throws java.sql.SQLException {
        statement.setUnicodeStream(a0, a1, a2);
    }

    @Override
    public <T> T unwrap(java.lang.Class<T> a0) throws java.sql.SQLException {
        return statement.unwrap(a0);
    }
}
