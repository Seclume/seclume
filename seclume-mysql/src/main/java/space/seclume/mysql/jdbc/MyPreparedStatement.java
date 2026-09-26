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
final class MyPreparedStatement extends MyStatement
        implements ParameterSetters, space.seclume.SensitiveParameters {

    private final String sql;
    private final MyParameters parameters = new MyParameters(8);
    private List<Object[]> batch;
    private boolean released;
    /** Lists bound to {@code in (?)}, by parameter index - see InLists; null for none. */
    private space.seclume.internal.jdbc.InLists.Bound[] lists;

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
     *
     * <p><b>Asked for on every execution, and never remembered here.</b> The
     * plan belongs to the session's cache, which is bounded and drops the
     * least recently used one - with a {@code COM_STMT_CLOSE} to the server.
     * A statement object that had kept the plan it was given would therefore
     * be holding a number the server has thrown away, and the next execution
     * fails with <i>Unknown prepared statement handler</i> - not where the
     * eviction happened, but in whatever ran next. That is reachable whenever
     * a statement outlives sixty-four other texts on the same connection,
     * which is ordinary for a pooled connection: the pool's own statement
     * cache hands the same object out again days later.
     *
     * <p>The lookup is a map lookup and it also marks the plan as the most
     * recently used one, so the plan of a statement that is executing cannot
     * be the one evicted to make room.
     */
    private MySession.Prepared prepare() throws SQLException {
        return connection.session().prepareCached(space.seclume.internal.jdbc.InLists.apply(
                sql, lists, space.seclume.internal.jdbc.InLists.Dialect.MYSQL));
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
            throw new SQLException("the statement returned no rows: " + shape(sql)
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
        underDeadline(sql, this::runPreparedNow);
    }

    private void runPreparedNow() throws SQLException {
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
        space.seclume.internal.jdbc.InLists.Bound list = space.seclume.internal.jdbc.InLists.of(
                value, space.seclume.internal.jdbc.InLists.Dialect.MYSQL);
        lists = space.seclume.internal.jdbc.InLists.note(lists, index, list);
        parameters.set(index, list == null ? value : list.payload());
    }

    @Override
    public void setSensitive(int parameterIndex, java.lang.foreign.MemorySegment value)
            throws SQLException {
        setParameter(parameterIndex, new space.seclume.internal.jdbc.NativeValue(value));
    }

    @Override
    public void clearParameters() throws SQLException {
        checkOpen();
        parameters.clear();
        lists = null;
    }

    // ---- batches ---------------------------------------------------------

    @Override
    public void addBatch() throws SQLException {
        checkOpen();
        space.seclume.internal.jdbc.InLists.refuseInBatch(lists);
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
        closeResult();
        List<Object[]> rows = batch;
        if (connection.rewriteBatchedInserts() && rows.size() > 1 && lists == null) {
            InsertBatch shape = InsertBatch.parse(sql);
            if (shape != null) {
                long[] counts;
                try {
                    counts = executeRewritten(shape, rows);
                } catch (SQLException failure) {
                    throw inDoubt(failure, null);
                } finally {
                    // The blocks bound many rows' worth; the next row the
                    // caller sets must start from one row's width again.
                    parameters.clear();
                }
                batch = null;
                return counts;
            }
        }
        MySession.Prepared statement = prepare();
        // Pipelined, not one round trip per row - see
        // MySession.executePreparedBatch. Connector/J sends them one by one
        // unless it is told otherwise, so this is where the difference is a
        // factor rather than a percentage.
        // A batch in auto-commit mode commits as it goes, so a lost answer
        // here is a lost commit - see inDoubt.
        long[] counts;
        try {
            counts = connection.session().executePreparedBatch(statement, parameters,
                    rows.size(), index -> {
                        Object[] values = rows.get(index);
                        parameters.clear();
                        for (int p = 0; p < values.length; p++) {
                            parameters.set(p + 1, values[p]);
                        }
                    });
        } catch (SQLException failure) {
            throw inDoubt(failure, null);
        }
        batch = null;
        return counts;
    }

    /** The most rows one multi-row insert carries; a power of two, see below. */
    private static final int MOST_ROWS = 128;
    /** MySQL's limit on placeholders in one prepared statement. */
    private static final int MOST_PLACEHOLDERS = 65535;

    /**
     * A batch of a plain insert as multi-row inserts: full blocks of
     * {@link #MOST_ROWS} rows (fewer when the placeholders would exceed
     * MySQL's limit), the rest in powers of two - so a statement has at most
     * eight shapes in the plan cache whatever the batch sizes, and the rows
     * keep their order. Each shape's blocks are pipelined like single rows.
     *
     * <p>What changes against row by row, and why it is not the default: a
     * block is one statement, so it succeeds or fails as a whole. The blocks
     * of one size are pipelined, so a failing block does not stop the others
     * sent with it; the batch stops after that group, and the
     * {@link java.sql.BatchUpdateException} carries a count for every row
     * sent - {@code EXECUTE_FAILED} for the rows of a failed block. The count
     * per row is 1 when
     * a block's affected rows add up to its row count, and
     * {@code SUCCESS_NO_INFO} otherwise ({@code INSERT IGNORE} skipping a row,
     * {@code ON DUPLICATE KEY UPDATE} counting two).
     */
    private long[] executeRewritten(InsertBatch shape, List<Object[]> rows) throws SQLException {
        int width = shape.parameters();
        int most = Integer.highestOneBit(Math.max(1, Math.min(MOST_ROWS,
                MOST_PLACEHOLDERS / width)));
        long[] counts = new long[rows.size()]; // seclume-allow: update counts, not a secret
        int at = 0;
        while (at < rows.size()) {
            int left = rows.size() - at;
            int size = Integer.highestOneBit(Math.min(most, left));
            int blocks = size == most ? left / size : 1;
            MySession.Prepared statement = connection.session().prepareCached(shape.sql(size));
            int base = at;
            long[] affected;
            java.sql.BatchUpdateException failed = null;
            try {
                affected = connection.session().executePreparedBatch(statement, parameters,
                        blocks, block -> {
                        parameters.clear();
                        for (int row = 0; row < size; row++) {
                            Object[] values = rows.get(base + block * size + row);
                            if (values.length != width) {
                                throw new SQLException("batch row " + (base + block * size + row
                                        + 1) + " has " + values.length + " values, the insert "
                                        + "takes " + width, "07001");
                            }
                            for (int p = 0; p < width; p++) {
                                parameters.set(row * width + p + 1, values[p]);
                            }
                        }
                    });
            } catch (java.sql.BatchUpdateException blockFailed) {
                failed = blockFailed;
                affected = blockFailed.getLargeUpdateCounts();
            }
            for (int block = 0; block < blocks; block++) {
                long each = affected[block] == java.sql.Statement.EXECUTE_FAILED
                        ? java.sql.Statement.EXECUTE_FAILED
                        : affected[block] == size ? 1 : java.sql.Statement.SUCCESS_NO_INFO;
                java.util.Arrays.fill(counts, base + block * size, base + (block + 1) * size, each);
            }
            at += blocks * size;
            if (failed != null) {
                // Per row, and only the rows that were sent: the rest never ran.
                throw new java.sql.BatchUpdateException(failed.getMessage(),
                        failed.getSQLState(), failed.getErrorCode(),
                        java.util.Arrays.copyOf(counts, at), failed.getCause());
            }
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

    // ---- metadata --------------------------------------------------------

    /**
     * MySQL describes the columns already when preparing - so the metadata is
     * available here without an execution.
     */
    @Override
    public ResultSetMetaData getMetaData() throws SQLException {
        checkOpen();
        List<MySession.Field> columns = prepare().fields();
        return columns.isEmpty() ? null
                : new MyResultSetMetaData(columns, connection.session().tinyInt1isBit());
    }

    @Override
    public ParameterMetaData getParameterMetaData() throws SQLException {
        checkOpen();
        return space.seclume.internal.jdbc.PlaceholderMetaData.ofText(sql);
    }

    @Override
    public void close() {
        // The plan stays with the connection - it is in the cache, and the
        // next statement with the same text takes it from there instead of
        // preparing it again. What is thrown away is only this wrapper.
        released = true;
        super.close();
    }

    /**
     * A statement named in a message, with its values taken out.
     *
     * <p>The text must not travel: a literal in it can be a password, a card
     * number or a person, and an exception message is precisely what ends up
     * in a log. The shape says which statement it was and carries none of
     * that - see {@link space.seclume.QueryFingerprint}.
     */
    private static String shape(String sql) {
        return space.seclume.QueryFingerprint.of(sql,
                space.seclume.QueryFingerprint.Dialect.MYSQL);
    }

}
