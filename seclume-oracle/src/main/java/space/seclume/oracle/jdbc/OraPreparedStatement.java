package space.seclume.oracle.jdbc;

import java.sql.ParameterMetaData;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import space.seclume.internal.jdbc.ParameterSetters;
import space.seclume.oracle.net.TtcBinds;

/**
 * A prepared statement for Oracle.
 *
 * <p>Oracle needs no separate preparation step on the wire: the text and the
 * values travel in the same message, and the server keeps the plan under the
 * text. So a prepared statement costs no round trip more than a plain one -
 * and it is still the one to use, because the values never enter the text.
 *
 * <p>JDBC's question mark becomes {@code :1}, {@code :2} and so on; see
 * {@link OraSqlRewriter} for why that is a read and not a replace.
 */
final class OraPreparedStatement extends OraStatement implements ParameterSetters {

    private final String originalSql;
    private final String sql;
    private final int parameterCount;
    private final TtcBinds parameters = new TtcBinds();
    private List<Object[]> batch;

    OraPreparedStatement(OraConnection connection, String sql) throws SQLException {
        super(connection);
        this.originalSql = sql;
        OraSqlRewriter.Rewritten rewritten = OraSqlRewriter.rewrite(sql);
        this.sql = rewritten.sql();
        this.parameterCount = rewritten.parameters();
    }

    // ---- executing -------------------------------------------------------

    @Override
    public boolean execute() throws SQLException {
        return run();
    }

    @Override
    public ResultSet executeQuery() throws SQLException {
        run();
        ResultSet result = currentResultSet();
        if (result == null) {
            throw new SQLException("the statement returned no rows: " + originalSql
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
        run();
        return Math.max(getLargeUpdateCount(), 0);
    }

    private boolean run() throws SQLException {
        checkOpen();
        if (parameters.count() < parameterCount) {
            throw new SQLException("the statement has " + parameterCount
                    + " parameters but only " + parameters.count() + " were set");
        }
        if (keyColumns != null) {
            // Oracle hands the keys back through the into binds, so the
            // statement text and the bind list both grow by the columns asked
            // for - see OraStatement#withReturningInto. Once, not once per
            // execution: a second run would send one bind too many and the
            // server answers ORA-01006.
            while (parameters.count() < parameterCount + keyColumns.length) {
                parameters.addOutput();
            }
            connection.session().expectReturning(keyColumns.length);
            boolean hasResult = run(OraStatement.withReturningInto(sql, keyColumns,
                    parameterCount + 1), parameters);
            keepAsGeneratedKeys(java.util.List.of(keyColumns), lastReturned());
            return hasResult;
        }
        return run(sql, parameters);
    }

    /** The columns whose keys the caller wants, or {@code null}. */
    private String[] keyColumns;

    void wantGeneratedKeys(String[] columns) {
        this.keyColumns = columns.clone();
    }

    // ---- parameters ------------------------------------------------------

    @Override
    public void setParameter(int index, Object value) throws SQLException {
        checkOpen();
        if (index > parameterCount) {
            throw new SQLException("the statement has " + parameterCount
                    + " parameters, so " + index + " does not exist");
        }
        parameters.set(index, value);
    }

    @Override
    public void clearParameters() throws SQLException {
        checkOpen();
        parameters.clear();
    }

    // ---- batches ---------------------------------------------------------

    @Override
    public void addBatch() throws SQLException {
        checkOpen();
        if (batch == null) {
            batch = new ArrayList<>();
        }
        Object[] snapshot = new Object[parameters.count()]; // seclume-allow: statement parameters, user payload and never a secret
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

    /**
     * The whole batch in <b>one</b> call.
     *
     * <p>Oracle runs a statement over an array of values: the message carries
     * the text once, the description of the variables once, and then one set
     * of values per row. Five hundred rows cost one round trip instead of five
     * hundred - and over a network that is not a percentage but a factor.
     *
     * <p>The description has to fit the widest row, so the values are walked
     * once to measure before they are written. That is cheap: the walk touches
     * the same objects the writing does.
     *
     * <p>What comes back is one number for the whole call, not one per row.
     * Where it equals the number of rows every row changed one, which is what
     * an insert does; anything else is reported as
     * {@code SUCCESS_NO_INFO}, because a made-up count per row would be worse
     * than an honest "the server did not say".
     */
    @Override
    public long[] executeLargeBatch() throws SQLException {
        checkOpen();
        if (batch == null || batch.isEmpty()) {
            return new long[0];
        }
        List<Object[]> values = batch;
        batch = null;
        long[] counts = new long[values.size()]; // seclume-allow: update counts, not a secret
        long touched = runBatch(values);
        for (int i = 0; i < counts.length; i++) {
            counts[i] = touched == counts.length ? 1 : Statement.SUCCESS_NO_INFO;
        }
        return counts;
    }

    private long runBatch(List<Object[]> values) throws SQLException {
        checkOpen();
        return runArray(sql, parameters, values.size(), row -> {
            Object[] set = values.get(row);
            parameters.clear();
            for (int p = 0; p < set.length; p++) {
                parameters.set(p + 1, set[p]);
            }
        });
    }

    @Override
    public int[] executeBatch() throws SQLException {
        long[] counts = executeLargeBatch();
        int[] small = new int[counts.length];
        for (int i = 0; i < counts.length; i++) {
            small[i] = (int) Math.min(counts[i], Integer.MAX_VALUE);
        }
        return small;
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

    // ---- metadata --------------------------------------------------------

    /**
     * The columns are known once the statement has run. Oracle would describe
     * them beforehand, but that is a round trip nobody asked for - whoever
     * needs the description after {@code executeQuery} gets it from the
     * result.
     */
    @Override
    public ResultSetMetaData getMetaData() throws SQLException {
        checkOpen();
        ResultSet result = currentResultSet();
        return result == null ? null : result.getMetaData();
    }

    @Override
    public ParameterMetaData getParameterMetaData() throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "seclume does not ask the server to describe the parameters - it encodes "
                + "every parameter from its Java type instead");
    }

    // ---- LOBs als Parameter ----------------------------------------------

    /**
     * A large value handed over as a stream.
     *
     * <p>These are read to the end and then sent as an ordinary parameter.
     * Said plainly rather than hidden: the value does pass through memory, so
     * a stream buys convenience here, not thrift. It is still the right thing
     * to offer - Hibernate and Spring Data reach for these methods on their
     * own, and refusing them turns a working mapping into a stack trace.
     *
     * <p>What makes it safe at all is that a long parameter now leaves the
     * driver in pieces: without {@code NsChannel.sendSplit} the server would
     * simply close the connection. See {@code docs/protocol/oracle-lob.md}.
     */
    @Override
    public void setCharacterStream(int index, java.io.Reader reader) throws SQLException {
        setString(index, readFully(reader));
    }

    @Override
    public void setCharacterStream(int index, java.io.Reader reader, int length)
            throws SQLException {
        setCharacterStream(index, reader, (long) length);
    }

    @Override
    public void setCharacterStream(int index, java.io.Reader reader, long length)
            throws SQLException {
        setString(index, readFully(reader, length));
    }

    @Override
    public void setNCharacterStream(int index, java.io.Reader reader) throws SQLException {
        setCharacterStream(index, reader);
    }

    @Override
    public void setNCharacterStream(int index, java.io.Reader reader, long length)
            throws SQLException {
        setCharacterStream(index, reader, length);
    }

    @Override
    public void setClob(int index, java.sql.Clob value) throws SQLException {
        if (value == null) {
            setNull(index, java.sql.Types.CLOB);
            return;
        }
        setCharacterStream(index, value.getCharacterStream());
    }

    @Override
    public void setClob(int index, java.io.Reader reader) throws SQLException {
        setCharacterStream(index, reader);
    }

    @Override
    public void setClob(int index, java.io.Reader reader, long length) throws SQLException {
        setCharacterStream(index, reader, length);
    }

    @Override
    public void setNClob(int index, java.sql.NClob value) throws SQLException {
        setClob(index, (java.sql.Clob) value);
    }

    @Override
    public void setNClob(int index, java.io.Reader reader) throws SQLException {
        setCharacterStream(index, reader);
    }

    @Override
    public void setNClob(int index, java.io.Reader reader, long length) throws SQLException {
        setCharacterStream(index, reader, length);
    }

    @Override
    public void setBinaryStream(int index, java.io.InputStream stream) throws SQLException {
        setBytes(index, readFully(stream));
    }

    @Override
    public void setBinaryStream(int index, java.io.InputStream stream, int length)
            throws SQLException {
        setBinaryStream(index, stream, (long) length);
    }

    @Override
    public void setBinaryStream(int index, java.io.InputStream stream, long length)
            throws SQLException {
        setBytes(index, readFully(stream, length));
    }

    @Override
    public void setBlob(int index, java.sql.Blob value) throws SQLException {
        if (value == null) {
            setNull(index, java.sql.Types.BLOB);
            return;
        }
        setBinaryStream(index, value.getBinaryStream());
    }

    @Override
    public void setBlob(int index, java.io.InputStream stream) throws SQLException {
        setBinaryStream(index, stream);
    }

    @Override
    public void setBlob(int index, java.io.InputStream stream, long length)
            throws SQLException {
        setBinaryStream(index, stream, length);
    }

    private static String readFully(java.io.Reader reader) throws SQLException {
        return readFully(reader, Long.MAX_VALUE);
    }

    private static String readFully(java.io.Reader reader, long limit) throws SQLException {
        if (reader == null) {
            return null;
        }
        StringBuilder text = new StringBuilder(); // seclume-allow: user payload, not a secret
        char[] buffer = new char[8192]; // seclume-allow: user payload, not a secret
        try (java.io.Reader open = reader) {
            while (text.length() < limit) {
                int wanted = (int) Math.min(buffer.length, limit - text.length());
                int read = open.read(buffer, 0, wanted);
                if (read < 0) {
                    break;
                }
                text.append(buffer, 0, read);
            }
        } catch (java.io.IOException e) {
            throw new SQLException("the reader for parameter failed: " + e.getMessage(), "22000", e);
        }
        return text.toString();
    }

    private static byte[] readFully(java.io.InputStream stream) throws SQLException {
        return readFully(stream, Long.MAX_VALUE);
    }

    private static byte[] readFully(java.io.InputStream stream, long limit) throws SQLException {
        if (stream == null) {
            return null;
        }
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[8192]; // seclume-allow: user payload, not a secret
        try (java.io.InputStream open = stream) {
            long total = 0;
            while (total < limit) {
                int wanted = (int) Math.min(buffer.length, limit - total);
                int read = open.read(buffer, 0, wanted);
                if (read < 0) {
                    break;
                }
                out.write(buffer, 0, read);
                total += read;
            }
        } catch (java.io.IOException e) {
            throw new SQLException("the stream for parameter failed: " + e.getMessage(), "22000", e);
        }
        return out.toByteArray();
    }
}
