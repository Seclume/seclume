package space.seclume.mysql.jdbc;

import java.sql.ParameterMetaData;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.ArrayList;
import java.util.List;

import space.seclume.internal.jdbc.ParameterSetters;
import space.seclume.mysql.MyParameters;
import space.seclume.mysql.MySession;

/**
 * A prepared statement in the binary protocol.
 *
 * <p>{@code COM_STMT_PREPARE} runs once, {@code COM_STMT_EXECUTE} on every
 * execution. The server keeps the plan for as long as the statement is open.
 *
 * <p>JDBC's question mark happens to be the character MySQL uses as well -
 * unlike with PostgreSQL, nothing about the SQL has to be rewritten.
 *
 * <p>Parameters go over the wire as parameters, never as text inside the SQL.
 * SQL injection is not a danger warded off here, it does not exist at all.
 */
final class MyPreparedStatement extends MyStatement implements ParameterSetters {

    private final String sql;
    private final MyParameters parameters = new MyParameters(8);
    private MySession.Prepared prepared;
    private List<Object[]> batch;
    private boolean released;

    MyPreparedStatement(MyConnection connection, String sql) {
        super(connection);
        this.sql = sql;
    }

    /**
     * The plan for this statement - from the connection's cache if it is
     * already there.
     *
     * <p>A framework builds a new {@code PreparedStatement} for every call, so
     * without the cache every call pays a round trip to prepare something the
     * server has long known. See {@link MySession#prepareCached}.
     */
    private MySession.Prepared prepare() throws SQLException {
        if (prepared == null) {
            prepared = connection.session().prepareCached(sql);
        }
        return prepared;
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
        MySession session = connection.session();
        if (session.isPipelining()) {
            // Inside a pipeline block: written now, sent later. The answer is
            // SUCCESS_NO_INFO because the count really is not known yet - see
            // space.seclume.Pipeline.
            MySession.Prepared statement = prepare();
            if (parameters.count() < statement.parameterCount()) {
                throw new SQLException("the statement has " + statement.parameterCount()
                        + " parameters but only " + parameters.count() + " were set");
            }
            return session.pipelineExecute(statement, parameters, sql);
        }
        runPrepared();
        return Math.max(updateCountValue(), 0);
    }

    private void runPrepared() throws SQLException {
        checkOpen();
        MySession.Prepared statement = prepare();
        if (parameters.count() < statement.parameterCount()) {
            throw new SQLException("the statement has " + statement.parameterCount()
                    + " parameters but only " + parameters.count() + " were set");
        }
        executePrepared(connection.session(), statement, parameters);
    }

    // ---- parameters ------------------------------------------------------

    @Override
    public void setParameter(int index, Object value) throws SQLException {
        checkOpen();
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
        MySession.Prepared statement = prepare();
        closeResult();
        List<Object[]> rows = batch;
        // Pipelined, not one round trip per row - see
        // MySession.executePreparedBatch. Connector/J sends them one by one
        // unless it is told otherwise, so this is where the difference is a
        // factor rather than a percentage.
        long[] counts = connection.session().executePreparedBatch(statement, parameters,
                rows.size(), index -> {
                    Object[] values = rows.get(index);
                    parameters.clear();
                    for (int p = 0; p < values.length; p++) {
                        parameters.set(p + 1, values[p]);
                    }
                });
        batch = null;
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

    // ---- metadata --------------------------------------------------------

    /**
     * MySQL describes the columns already when preparing - so the metadata is
     * available here without an execution.
     */
    @Override
    public ResultSetMetaData getMetaData() throws SQLException {
        checkOpen();
        List<MySession.Field> columns = prepare().fields();
        return columns.isEmpty() ? null : new MyResultSetMetaData(columns);
    }

    @Override
    public ParameterMetaData getParameterMetaData() throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "seclume does not read the parameter descriptions the server sends - it "
                + "encodes every parameter from its Java type instead");
    }

    @Override
    public void close() {
        // The plan stays with the connection - it is in the cache, and the
        // next statement with the same text takes it from there instead of
        // preparing it again. What is thrown away is only this wrapper.
        released = true;
        super.close();
    }
}
