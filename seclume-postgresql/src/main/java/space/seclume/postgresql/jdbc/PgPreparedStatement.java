package space.seclume.postgresql.jdbc;

import java.io.InputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.net.URL;
import java.sql.Array;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Date;
import java.sql.NClob;
import java.sql.ParameterMetaData;
import java.sql.PreparedStatement;
import java.sql.Ref;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLXML;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import space.seclume.postgresql.PgParameters;
import space.seclume.postgresql.PgSession;

/**
 * A prepared statement in the extended protocol.
 *
 * <p>{@code Parse} runs once, {@code Bind}/{@code Execute} on every execution.
 * The server keeps the plan for as long as the statement is open.
 *
 * <p>Parameters go over the wire as parameters, never as text inside the SQL.
 * With that there is no SQL injection here - not because something gets
 * escaped, but because values and statement are separate fields of the same
 * message.
 */
final class PgPreparedStatement extends PgStatement implements PreparedStatement {

    private final String sql;
    private final String name;
    private final PgParameters parameters;
    private final int expectedParameters;
    private List<PgSession.Field> described;
    private List<Object[]> batch;
    private boolean prepared;
    private boolean released;

    PgPreparedStatement(PgConnection connection, String sql, String name) throws SQLException {
        super(connection);
        // PostgreSQL knows no question marks; $1, $2 ... are its placeholders.
        PgSqlRewriter.Rewritten rewritten = PgSqlRewriter.rewrite(sql);
        this.sql = rewritten.sql();
        this.expectedParameters = rewritten.parameters();
        this.name = name;
        this.parameters = new PgParameters(Math.max(rewritten.parameters(), 8));
    }

    /**
     * Announces the plan; the server parses it with the first execution.
     *
     * <p>A {@code Parse} of its own would be a round trip whose answer nobody
     * needs yet - sent together with the first {@code Bind} and
     * {@code Execute}, it costs nothing. Whoever asks for the column
     * description before running the statement gets it, and pays the round
     * trip then; see {@link #getMetaData()}.
     */
    private void prepare() throws SQLException {
        if (!prepared) {
            connection.session().parseLater(name, sql);
            prepared = true;
        }
    }

    /** Forces the announced plan to be parsed now, because somebody asks. */
    private void describeNow() throws SQLException {
        prepare();
        if (described == null && connection.session().hasPendingParse()) {
            described = connection.session().parse(name, sql);
        }
    }

    // ---- executing -------------------------------------------------------

    @Override
    public boolean execute() throws SQLException {
        runPrepared();
        return currentResultSet() != null;
    }

    @Override
    public ResultSet executeQuery() throws SQLException {
        runPrepared();
        ResultSet result = currentResultSet();
        if (result == null) {
            throw new SQLException("the statement returned no rows: " + sql
                    + " - use executeUpdate for statements that do not select");
        }
        return result;
    }

    @Override
    public int executeUpdate() throws SQLException {
        return (int) Math.min(executeLargeUpdate(), Integer.MAX_VALUE);
    }

    @Override
    public long executeLargeUpdate() throws SQLException {
        checkOpen();
        PgSession session = connection.session();
        if (session.isPipelining()) {
            // Inside a pipeline block: written now, sent later. The answer is
            // SUCCESS_NO_INFO because the count really is not known yet - see
            // space.seclume.Pipeline.
            return buffered(session);
        }
        runPrepared();
        if (wantsGeneratedKeys()) {
            // The rewritten statement answered with rows; they are the keys,
            // not a result the caller iterates.
            keepAsGeneratedKeys();
        }
        return Math.max(updateCountValue(), 0);
    }

    /** One execution into the block, without waiting for its count. */
    private long buffered(PgSession session) throws SQLException {
        prepare();
        if (parameters.count() < expectedParameters) {
            throw new SQLException("the statement has " + expectedParameters
                    + " parameters but only " + parameters.count() + " were set");
        }
        return session.pipelineBindAndExecute(name, parameters, sql);
    }

    private void runPrepared() throws SQLException {
        checkOpen();
        prepare();
        if (parameters.count() < expectedParameters) {
            throw new SQLException("the statement has " + expectedParameters
                    + " parameters but only " + parameters.count() + " were set");
        }
        PgSession session = connection.session();
        decideStreaming(true);
        beginExecution(session, parameters, name, executeLimit(), sql);
    }

    // ---- batches ---------------------------------------------------------

    @Override
    public void addBatch() throws SQLException {
        checkOpen();
        if (batch == null) {
            batch = new ArrayList<>();
        }
        Object[] snapshot = new Object[parameters.count()];
        for (int i = 0; i < snapshot.length; i++) {
            snapshot[i] = parameters.get(i + 1);
        }
        batch.add(snapshot);
    }

    @Override
    public void clearBatch() throws SQLException {
        checkOpen();
        batch = null;
        super.clearBatch();
    }

    @Override
    public long[] executeLargeBatch() throws SQLException {
        checkOpen();
        if (batch == null || batch.isEmpty()) {
            return super.executeLargeBatch();
        }
        prepare();
        closeResult();
        List<Object[]> rows = batch;
        batch = null;
        // Pipelined, not one round trip per row: the whole point of a batch.
        // Sent row by row, five hundred inserts cost five hundred times the
        // latency of the network while the database waits - measured at fifty
        // times the pipelined path on a loopback connection, and the gap grows
        // with every millisecond of distance to the server.
        long[] counts = connection.session().bindAndExecuteBatch(name, parameters,
                rows.size(), index -> {
                    Object[] values = rows.get(index);
                    parameters.clear();
                    for (int p = 0; p < values.length; p++) {
                        parameters.set(p + 1, values[p]);
                    }
                });
        for (int i = 0; i < counts.length; i++) {
            counts[i] = Math.max(counts[i], 0);
        }
        return counts;
    }

    @Override
    public void addBatch(String otherSql) throws SQLException {
        throw new SQLException("this is a prepared statement - use addBatch() without SQL");
    }

    @Override
    public boolean execute(String otherSql) throws SQLException {
        throw new SQLException("this is a prepared statement - use execute() without SQL");
    }

    @Override
    public ResultSet executeQuery(String otherSql) throws SQLException {
        throw new SQLException("this is a prepared statement - use executeQuery() without SQL");
    }

    @Override
    public int executeUpdate(String otherSql) throws SQLException {
        throw new SQLException("this is a prepared statement - use executeUpdate() without SQL");
    }

    // ---- parameters ------------------------------------------------------

    @Override
    public void clearParameters() throws SQLException {
        checkOpen();
        parameters.clear();
    }

    @Override
    public void setNull(int index, int sqlType) throws SQLException {
        set(index, null);
    }

    @Override
    public void setNull(int index, int sqlType, String typeName) throws SQLException {
        set(index, null);
    }

    @Override
    public void setBoolean(int index, boolean value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setByte(int index, byte value) throws SQLException {
        set(index, (short) value);
    }

    @Override
    public void setShort(int index, short value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setInt(int index, int value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setLong(int index, long value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setFloat(int index, float value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setDouble(int index, double value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setBigDecimal(int index, BigDecimal value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setString(int index, String value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setBytes(int index, byte[] value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setDate(int index, Date value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setTime(int index, Time value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setTimestamp(int index, Timestamp value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setDate(int index, Date value, Calendar calendar) throws SQLException {
        requireDefaultCalendar(calendar);
        set(index, value);
    }

    @Override
    public void setTime(int index, Time value, Calendar calendar) throws SQLException {
        requireDefaultCalendar(calendar);
        set(index, value);
    }

    @Override
    public void setTimestamp(int index, Timestamp value, Calendar calendar) throws SQLException {
        requireDefaultCalendar(calendar);
        set(index, value);
    }

    @Override
    public void setObject(int index, Object value) throws SQLException {
        set(index, value);
    }

    @Override
    public void setObject(int index, Object value, int targetSqlType) throws SQLException {
        set(index, value);
    }

    @Override
    public void setObject(int index, Object value, int targetSqlType, int scale) throws SQLException {
        set(index, value);
    }

    private void set(int index, Object value) throws SQLException {
        checkOpen();
        parameters.set(index, value);
    }

    /**
     * A foreign calendar would call for a time-zone conversion this driver
     * does not do - ignoring that silently would be a data error that only
     * surfaces months later.
     */
    private void requireDefaultCalendar(Calendar calendar) throws SQLException {
        if (calendar != null
                && !calendar.getTimeZone().equals(java.util.TimeZone.getDefault())) {
            throw new SQLFeatureNotSupportedException(
                    "seclume sends dates and times in the JVM's time zone - pass an "
                    + "OffsetDateTime if you need a specific zone");
        }
    }

    // ---- metadata --------------------------------------------------------

    @Override
    public ResultSetMetaData getMetaData() throws SQLException {
        checkOpen();
        prepare();
        describeNow();
        return described == null || described.isEmpty() ? null : new PgResultSetMetaData(described);
    }

    @Override
    public ParameterMetaData getParameterMetaData() throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "seclume does not ask the server for parameter types - it sends every "
                + "parameter in text form and lets the server decide");
    }

    // ---- the unsupported remainder ---------------------------------------

    @Override
    public void setAsciiStream(int index, InputStream stream, int length) throws SQLException {
        throw streams();
    }

    @SuppressWarnings("deprecation")
    @Override
    public void setUnicodeStream(int index, InputStream stream, int length) throws SQLException {
        throw streams();
    }

    @Override
    public void setBinaryStream(int index, InputStream stream, int length) throws SQLException {
        throw streams();
    }

    @Override
    public void setAsciiStream(int index, InputStream stream, long length) throws SQLException {
        throw streams();
    }

    @Override
    public void setBinaryStream(int index, InputStream stream, long length) throws SQLException {
        throw streams();
    }

    @Override
    public void setAsciiStream(int index, InputStream stream) throws SQLException {
        throw streams();
    }

    @Override
    public void setBinaryStream(int index, InputStream stream) throws SQLException {
        throw streams();
    }

    @Override
    public void setCharacterStream(int index, Reader reader, int length) throws SQLException {
        throw streams();
    }

    @Override
    public void setCharacterStream(int index, Reader reader, long length) throws SQLException {
        throw streams();
    }

    @Override
    public void setCharacterStream(int index, Reader reader) throws SQLException {
        throw streams();
    }

    @Override
    public void setNCharacterStream(int index, Reader reader, long length) throws SQLException {
        throw streams();
    }

    @Override
    public void setNCharacterStream(int index, Reader reader) throws SQLException {
        throw streams();
    }

    private static SQLFeatureNotSupportedException streams() {
        return new SQLFeatureNotSupportedException(
                "seclume does not take streams as parameters - read the value yourself "
                + "and pass a String or byte[], so the size stays visible at the call site");
    }

    @Override
    public void setRef(int index, Ref value) throws SQLException {
        throw unsupported("REF");
    }

    @Override
    public void setBlob(int index, Blob value) throws SQLException {
        throw unsupported("BLOB");
    }

    @Override
    public void setBlob(int index, InputStream stream, long length) throws SQLException {
        throw unsupported("BLOB");
    }

    @Override
    public void setBlob(int index, InputStream stream) throws SQLException {
        throw unsupported("BLOB");
    }

    @Override
    public void setClob(int index, Clob value) throws SQLException {
        throw unsupported("CLOB");
    }

    @Override
    public void setClob(int index, Reader reader, long length) throws SQLException {
        throw unsupported("CLOB");
    }

    @Override
    public void setClob(int index, Reader reader) throws SQLException {
        throw unsupported("CLOB");
    }

    @Override
    public void setNClob(int index, NClob value) throws SQLException {
        throw unsupported("NCLOB");
    }

    @Override
    public void setNClob(int index, Reader reader, long length) throws SQLException {
        throw unsupported("NCLOB");
    }

    @Override
    public void setNClob(int index, Reader reader) throws SQLException {
        throw unsupported("NCLOB");
    }

    @Override
    public void setArray(int index, Array value) throws SQLException {
        throw unsupported("ARRAY");
    }

    @Override
    public void setRowId(int index, RowId value) throws SQLException {
        throw unsupported("ROWID");
    }

    @Override
    public void setSQLXML(int index, SQLXML value) throws SQLException {
        throw unsupported("SQLXML");
    }

    @Override
    public void setNString(int index, String value) throws SQLException {
        // PostgreSQL has no separate N-character format; text is always Unicode.
        set(index, value);
    }

    @Override
    public void setURL(int index, URL value) throws SQLException {
        throw unsupported("URL");
    }

    private static SQLFeatureNotSupportedException unsupported(String type) {
        return new SQLFeatureNotSupportedException(
                "seclume does not send " + type + " parameters yet");
    }

    @Override
    public void close() {
        if (!isClosed() && prepared && !released) {
            released = true;
            try {
                // Rides along with the next statement. Nobody waits for the
                // answer to a close - the method returns nothing - and if the
                // connection ends first, the plan goes with it anyway. The
                // answer is still read and still checked, just one round trip
                // later.
                connection.session().closeStatementLater(name);
            } catch (SQLException ignored) {
                // On close the server plan is the lesser problem; it goes
                // away with the connection at the latest anyway.
            }
        }
        super.close();
    }
}
