package space.seclume.sqlserver.jdbc;

import java.sql.ParameterMetaData;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.ArrayList;
import java.util.List;

import space.seclume.internal.jdbc.ParameterSetters;
import space.seclume.sqlserver.tds.TdsParameters;
import space.seclume.sqlserver.tds.TdsSession;

/**
 * A prepared statement, run through {@code sp_executesql}.
 *
 * <p>SQL Server needs no separate preparation step for this: the text goes over
 * with every execution, and the server caches the plan under it. That is one
 * round trip less than {@code sp_prepare} plus {@code sp_execute}, and from the
 * second call on the plan is the same one - which is exactly what a prepared
 * statement is for.
 *
 * <p>JDBC's question mark becomes {@code @P0}, {@code @P1} and so on; see
 * {@link TdsSqlRewriter} for why that is a read and not a replace.
 *
 * <p>Parameters travel as parameters, never as text inside the SQL. SQL
 * injection is not a danger warded off here, it does not exist on this path.
 */
final class TdsPreparedStatement extends TdsStatement implements ParameterSetters {

    private final String originalSql;
    private final String sql;
    private final int parameterCount;
    private final TdsParameters parameters = new TdsParameters();
    private List<Object[]> batch;

    TdsPreparedStatement(TdsConnection connection, String sql) throws SQLException {
        super(connection);
        this.originalSql = sql;
        TdsSqlRewriter.Rewritten rewritten = TdsSqlRewriter.rewrite(sql);
        this.sql = rewritten.sql();
        this.parameterCount = rewritten.parameters();
    }

    // ---- executing -------------------------------------------------------

    @Override
    public boolean execute() throws SQLException {
        run();
        return currentResultSet() != null;
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

    private void run() throws SQLException {
        checkOpen();
        if (parameters.count() < parameterCount) {
            throw new SQLException("the statement has " + parameterCount
                    + " parameters but only " + parameters.count() + " were set");
        }
        TdsSession session = connection.session();
        String declaration = parameters.declaration();
        // A fetch size means the server keeps the rows and hands them out in
        // blocks - see TdsStatement#openCursor. Only without bind values so
        // far: sp_cursorprepexec refuses this driver's parameter list, and a
        // half-understood call is worse than none. The statement then reads
        // the whole result, exactly as it did before.
        if (getFetchSize() > 0 && declaration.isEmpty()) {
            openCursor(session, sql, declaration, parameters);
            return;
        }
        collect(session, handler -> session.rpc(sql, declaration, parameters, handler));
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
     * The whole batch in as few messages as the protocol allows.
     *
     * <p>TDS lets several RPCs travel in one request, separated by a single
     * byte - and each of them carries its own parameters <b>and their
     * types</b>. The old objection to bundling ("only with the same types
     * throughout") was about a different technique and does not apply here: a
     * batch in which one row passes {@code null} and the next a number is
     * fine.
     *
     * <p>Sent row by row this cost one round trip per row. That is the whole
     * of the time on any network worth the name.
     */
    @Override
    public long[] executeLargeBatch() throws SQLException {
        checkOpen();
        if (batch == null || batch.isEmpty()) {
            return new long[0];
        }
        List<Object[]> rows = batch;
        batch = null;
        TdsSession session = connection.session();
        return session.rpcBatch(sql, parameters, rows.size(), row -> {
            Object[] values = rows.get(row);
            parameters.clear();
            for (int p = 0; p < values.length; p++) {
                parameters.set(p + 1, values[p]);
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
     * The columns are only known once the statement has run - SQL Server would
     * describe them beforehand through {@code sp_describe_first_result_set},
     * but that is a second round trip that nobody asked for. Whoever needs the
     * description after {@code executeQuery} gets it from the result.
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
}
