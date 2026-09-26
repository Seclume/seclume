package space.seclume.pool;

import java.io.InputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.net.URL;
import java.sql.Array;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.Date;
import java.sql.NClob;
import java.sql.ParameterMetaData;
import java.sql.PreparedStatement;
import java.sql.Ref;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLType;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Statement;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.Calendar;

/**
 * The handle an application holds on a cached statement.
 *
 * <p>JDBC says a closed statement is unusable, and the cache says the statement
 * lives on. Both are true at once because what the caller holds is not the
 * statement: it is a handle whose {@code close()} gives the statement back to
 * the cache and then refuses everything, exactly as a closed one would.
 *
 * <p><b>Written out rather than proxied - and not for the reason it was first
 * changed for.</b> This was a {@code Proxy}, and it was rewritten on
 * 22.09.2026 in the belief that a native image would refuse one. That belief
 * was wrong, and the control run says so: GraalVM 25 builds and runs a proxy
 * whose interface is a class literal without being told anything. The change
 * was kept because what it buys turned out to be better than the reason given
 * for it.
 *
 * <p>What it buys is the compiler. The proxy existed because {@code
 * PreparedStatement} has a hundred methods and forgetting one would send a call
 * quietly to a statement the caller believes is closed - and a concrete class
 * that says {@code implements PreparedStatement} does not build with a method
 * missing. The risk moved out of a comment and into javac. What javac cannot
 * check is that each method goes through the guard, and that is what
 * {@code DelegationIsCompleteTest} counts.
 *
 * <p>The guard is not repeated a hundred times: {@link #open()} is the one
 * place that decides whether this handle is still usable.
 */
final class CachedPreparedStatement implements PreparedStatement {

    private final StatementCache cache;
    private final String sql;
    private final PreparedStatement statement;
    private boolean given;

    private CachedPreparedStatement(StatementCache cache, String sql,
                                    PreparedStatement statement) {
        this.cache = cache;
        this.sql = sql;
        this.statement = statement;
    }

    /** Wraps a statement so that closing it returns it to the cache. */
    static PreparedStatement wrap(StatementCache cache, String sql,
                                  PreparedStatement statement, Connection handle) {
        CachedPreparedStatement wrapped = new CachedPreparedStatement(cache, sql, statement);
        wrapped.handle = handle;
        return wrapped;
    }

    /**
     * The pool handle this was taken through. The statement behind it lives
     * across borrowers, so it cannot know which one holds it now.
     */
    private Connection handle;

    /**
     * The statement, if this handle may still be used.
     *
     * <p>One place, called by every delegating method below. A guard written
     * out per method would be a hundred chances to leave it out.
     */
    private PreparedStatement open() throws SQLException {
        if (given) {
            throw new SQLException("this prepared statement was closed", "HY010");
        }
        return statement;
    }

    /** Gives the statement back to the cache; the handle refuses from here. */
    @Override
    public void close() throws SQLException {
        if (!given) {
            given = true;
            if (!cache.give(sql, statement)) {
                statement.close();
            }
        }
    }

    @Override
    public boolean isClosed() throws SQLException {
        return given || statement.isClosed();
    }

    // ---- everything else goes straight through ----------------------------

    @Override
    public void addBatch() throws SQLException {
        open().addBatch();
    }

    @Override
    public void addBatch(String a0) throws SQLException {
        open().addBatch(a0);
    }

    @Override
    public void cancel() throws SQLException {
        open().cancel();
    }

    @Override
    public void clearBatch() throws SQLException {
        open().clearBatch();
    }

    @Override
    public void clearParameters() throws SQLException {
        open().clearParameters();
    }

    @Override
    public void clearWarnings() throws SQLException {
        open().clearWarnings();
    }

    @Override
    public void closeOnCompletion() throws SQLException {
        open().closeOnCompletion();
    }

    @Override
    public boolean execute() throws SQLException {
        return open().execute();
    }

    @Override
    public boolean execute(String a0, int[] a1) throws SQLException {
        return open().execute(a0, a1);
    }

    @Override
    public boolean execute(String a0, String[] a1) throws SQLException {
        return open().execute(a0, a1);
    }

    @Override
    public boolean execute(String a0, int a1) throws SQLException {
        return open().execute(a0, a1);
    }

    @Override
    public boolean execute(String a0) throws SQLException {
        return open().execute(a0);
    }

    @Override
    public int[] executeBatch() throws SQLException {
        return open().executeBatch();
    }

    @Override
    public ResultSet executeQuery() throws SQLException {
        return open().executeQuery();
    }

    @Override
    public ResultSet executeQuery(String a0) throws SQLException {
        return open().executeQuery(a0);
    }

    @Override
    public int executeUpdate() throws SQLException {
        return open().executeUpdate();
    }

    @Override
    public int executeUpdate(String a0, int[] a1) throws SQLException {
        return open().executeUpdate(a0, a1);
    }

    @Override
    public int executeUpdate(String a0, String[] a1) throws SQLException {
        return open().executeUpdate(a0, a1);
    }

    @Override
    public int executeUpdate(String a0, int a1) throws SQLException {
        return open().executeUpdate(a0, a1);
    }

    @Override
    public int executeUpdate(String a0) throws SQLException {
        return open().executeUpdate(a0);
    }

    @Override
    public Connection getConnection() throws SQLException {
        Connection underneath = open().getConnection();
        return handle != null ? handle : underneath;
    }

    @Override
    public int getFetchDirection() throws SQLException {
        return open().getFetchDirection();
    }

    @Override
    public int getFetchSize() throws SQLException {
        return open().getFetchSize();
    }

    @Override
    public ResultSet getGeneratedKeys() throws SQLException {
        return open().getGeneratedKeys();
    }

    @Override
    public int getMaxFieldSize() throws SQLException {
        return open().getMaxFieldSize();
    }

    @Override
    public int getMaxRows() throws SQLException {
        return open().getMaxRows();
    }

    @Override
    public ResultSetMetaData getMetaData() throws SQLException {
        return open().getMetaData();
    }

    @Override
    public boolean getMoreResults() throws SQLException {
        return open().getMoreResults();
    }

    @Override
    public boolean getMoreResults(int a0) throws SQLException {
        return open().getMoreResults(a0);
    }

    @Override
    public ParameterMetaData getParameterMetaData() throws SQLException {
        return open().getParameterMetaData();
    }

    @Override
    public int getQueryTimeout() throws SQLException {
        return open().getQueryTimeout();
    }

    @Override
    public ResultSet getResultSet() throws SQLException {
        return open().getResultSet();
    }

    @Override
    public int getResultSetConcurrency() throws SQLException {
        return open().getResultSetConcurrency();
    }

    @Override
    public int getResultSetHoldability() throws SQLException {
        return open().getResultSetHoldability();
    }

    @Override
    public int getResultSetType() throws SQLException {
        return open().getResultSetType();
    }

    @Override
    public int getUpdateCount() throws SQLException {
        return open().getUpdateCount();
    }

    @Override
    public SQLWarning getWarnings() throws SQLException {
        return open().getWarnings();
    }

    @Override
    public boolean isCloseOnCompletion() throws SQLException {
        return open().isCloseOnCompletion();
    }

    @Override
    public boolean isPoolable() throws SQLException {
        return open().isPoolable();
    }

    @Override
    public boolean isWrapperFor(Class<?> a0) throws SQLException {
        return open().isWrapperFor(a0);
    }

    @Override
    public void setArray(int a0, Array a1) throws SQLException {
        open().setArray(a0, a1);
    }

    @Override
    public void setAsciiStream(int a0, InputStream a1, int a2) throws SQLException {
        open().setAsciiStream(a0, a1, a2);
    }

    @Override
    public void setAsciiStream(int a0, InputStream a1, long a2) throws SQLException {
        open().setAsciiStream(a0, a1, a2);
    }

    @Override
    public void setAsciiStream(int a0, InputStream a1) throws SQLException {
        open().setAsciiStream(a0, a1);
    }

    @Override
    public void setBigDecimal(int a0, BigDecimal a1) throws SQLException {
        open().setBigDecimal(a0, a1);
    }

    @Override
    public void setBinaryStream(int a0, InputStream a1, int a2) throws SQLException {
        open().setBinaryStream(a0, a1, a2);
    }

    @Override
    public void setBinaryStream(int a0, InputStream a1, long a2) throws SQLException {
        open().setBinaryStream(a0, a1, a2);
    }

    @Override
    public void setBinaryStream(int a0, InputStream a1) throws SQLException {
        open().setBinaryStream(a0, a1);
    }

    @Override
    public void setBlob(int a0, InputStream a1, long a2) throws SQLException {
        open().setBlob(a0, a1, a2);
    }

    @Override
    public void setBlob(int a0, InputStream a1) throws SQLException {
        open().setBlob(a0, a1);
    }

    @Override
    public void setBlob(int a0, Blob a1) throws SQLException {
        open().setBlob(a0, a1);
    }

    @Override
    public void setBoolean(int a0, boolean a1) throws SQLException {
        open().setBoolean(a0, a1);
    }

    @Override
    public void setByte(int a0, byte a1) throws SQLException {
        open().setByte(a0, a1);
    }

    @Override
    public void setBytes(int a0, byte[] a1) throws SQLException {
        open().setBytes(a0, a1);
    }

    @Override
    public void setCharacterStream(int a0, Reader a1, int a2) throws SQLException {
        open().setCharacterStream(a0, a1, a2);
    }

    @Override
    public void setCharacterStream(int a0, Reader a1, long a2) throws SQLException {
        open().setCharacterStream(a0, a1, a2);
    }

    @Override
    public void setCharacterStream(int a0, Reader a1) throws SQLException {
        open().setCharacterStream(a0, a1);
    }

    @Override
    public void setClob(int a0, Reader a1, long a2) throws SQLException {
        open().setClob(a0, a1, a2);
    }

    @Override
    public void setClob(int a0, Reader a1) throws SQLException {
        open().setClob(a0, a1);
    }

    @Override
    public void setClob(int a0, Clob a1) throws SQLException {
        open().setClob(a0, a1);
    }

    @Override
    public void setCursorName(String a0) throws SQLException {
        open().setCursorName(a0);
    }

    @Override
    public void setDate(int a0, Date a1, Calendar a2) throws SQLException {
        open().setDate(a0, a1, a2);
    }

    @Override
    public void setDate(int a0, Date a1) throws SQLException {
        open().setDate(a0, a1);
    }

    @Override
    public void setDouble(int a0, double a1) throws SQLException {
        open().setDouble(a0, a1);
    }

    @Override
    public void setEscapeProcessing(boolean a0) throws SQLException {
        open().setEscapeProcessing(a0);
    }

    @Override
    public void setFetchDirection(int a0) throws SQLException {
        open().setFetchDirection(a0);
    }

    @Override
    public void setFetchSize(int a0) throws SQLException {
        open().setFetchSize(a0);
    }

    @Override
    public void setFloat(int a0, float a1) throws SQLException {
        open().setFloat(a0, a1);
    }

    @Override
    public void setInt(int a0, int a1) throws SQLException {
        open().setInt(a0, a1);
    }

    @Override
    public void setLong(int a0, long a1) throws SQLException {
        open().setLong(a0, a1);
    }

    @Override
    public void setMaxFieldSize(int a0) throws SQLException {
        open().setMaxFieldSize(a0);
    }

    @Override
    public void setMaxRows(int a0) throws SQLException {
        open().setMaxRows(a0);
    }

    @Override
    public void setNCharacterStream(int a0, Reader a1, long a2) throws SQLException {
        open().setNCharacterStream(a0, a1, a2);
    }

    @Override
    public void setNCharacterStream(int a0, Reader a1) throws SQLException {
        open().setNCharacterStream(a0, a1);
    }

    @Override
    public void setNClob(int a0, Reader a1, long a2) throws SQLException {
        open().setNClob(a0, a1, a2);
    }

    @Override
    public void setNClob(int a0, Reader a1) throws SQLException {
        open().setNClob(a0, a1);
    }

    @Override
    public void setNClob(int a0, NClob a1) throws SQLException {
        open().setNClob(a0, a1);
    }

    @Override
    public void setNString(int a0, String a1) throws SQLException {
        open().setNString(a0, a1);
    }

    @Override
    public void setNull(int a0, int a1, String a2) throws SQLException {
        open().setNull(a0, a1, a2);
    }

    @Override
    public void setNull(int a0, int a1) throws SQLException {
        open().setNull(a0, a1);
    }

    @Override
    public void setObject(int a0, Object a1, int a2, int a3) throws SQLException {
        open().setObject(a0, a1, a2, a3);
    }

    @Override
    public void setObject(int a0, Object a1, int a2) throws SQLException {
        open().setObject(a0, a1, a2);
    }

    @Override
    public void setObject(int a0, Object a1) throws SQLException {
        open().setObject(a0, a1);
    }

    @Override
    public void setPoolable(boolean a0) throws SQLException {
        open().setPoolable(a0);
    }

    @Override
    public void setQueryTimeout(int a0) throws SQLException {
        open().setQueryTimeout(a0);
    }

    @Override
    public void setRef(int a0, Ref a1) throws SQLException {
        open().setRef(a0, a1);
    }

    @Override
    public void setRowId(int a0, RowId a1) throws SQLException {
        open().setRowId(a0, a1);
    }

    @Override
    public void setSQLXML(int a0, SQLXML a1) throws SQLException {
        open().setSQLXML(a0, a1);
    }

    @Override
    public void setShort(int a0, short a1) throws SQLException {
        open().setShort(a0, a1);
    }

    @Override
    public void setString(int a0, String a1) throws SQLException {
        open().setString(a0, a1);
    }

    @Override
    public void setTime(int a0, Time a1, Calendar a2) throws SQLException {
        open().setTime(a0, a1, a2);
    }

    @Override
    public void setTime(int a0, Time a1) throws SQLException {
        open().setTime(a0, a1);
    }

    @Override
    public void setTimestamp(int a0, Timestamp a1, Calendar a2) throws SQLException {
        open().setTimestamp(a0, a1, a2);
    }

    @Override
    public void setTimestamp(int a0, Timestamp a1) throws SQLException {
        open().setTimestamp(a0, a1);
    }

    @Override
    public void setURL(int a0, URL a1) throws SQLException {
        open().setURL(a0, a1);
    }

    /** Deprecated since JDBC 2.0 and still on the interface, so still here. */
    @Override
    @Deprecated
    @SuppressWarnings("deprecation")
    public void setUnicodeStream(int a0, InputStream a1, int a2) throws SQLException {
        open().setUnicodeStream(a0, a1, a2);
    }

    @Override
    public <T> T unwrap(Class<T> a0) throws SQLException {
        return open().unwrap(a0);
    }
}
