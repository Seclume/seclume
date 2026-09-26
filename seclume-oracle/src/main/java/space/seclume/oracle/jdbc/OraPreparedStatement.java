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
final class OraPreparedStatement extends OraStatement implements ParameterSetters,
        space.seclume.SensitiveParameters {

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
            throw new SQLException("the statement returned no rows: " + shape(originalSql)
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
        if (connection.session().isPipelining() && keyColumns == null) {
            // Inside a pipeline block this goes out without waiting for the
            // answer - see Pipeline. Generated keys are excluded because
            // Oracle returns them through output binds, which have to be read
            // before the next call: a block that sent them anyway would hand
            // one statement's keys to another.
            if (parameters.count() < parameterCount) {
                throw new SQLException("the statement has " + parameterCount
                        + " parameters but only " + parameters.count() + " were set");
            }
            return connection.session().pipelineExecute(currentSql(), parameters);
        }
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
            boolean hasResult = run(OraStatement.withReturningInto(currentSql(), keyColumns,
                    parameterCount + 1), parameters);
            keepAsGeneratedKeys(java.util.List.of(keyColumns), lastReturned());
            return hasResult;
        }
        return run(currentSql(), parameters);
    }

    /** Lists bound to {@code in (?)}, by parameter index - see InLists; null for none. */
    private space.seclume.internal.jdbc.InLists.Bound[] lists;
    /** The statement text the lists were last applied to, and what it became. */
    private String listSource;
    private String listSql;

    /** The text to send: the statement's own, or its form for the bound lists. */
    private String currentSql() throws SQLException {
        if (!space.seclume.internal.jdbc.InLists.any(lists)) {
            return sql;
        }
        String applied = space.seclume.internal.jdbc.InLists.apply(originalSql, lists,
                space.seclume.internal.jdbc.InLists.Dialect.ORACLE);
        if (!applied.equals(listSource)) {
            listSource = applied;
            listSql = OraSqlRewriter.rewrite(applied).sql();
        }
        return listSql;
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
        space.seclume.internal.jdbc.InLists.Bound list = space.seclume.internal.jdbc.InLists.of(
                value, space.seclume.internal.jdbc.InLists.Dialect.ORACLE);
        lists = space.seclume.internal.jdbc.InLists.note(lists, index, list);
        parameters.set(index, list == null ? value : list.payload());
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
        // A batch in auto-commit mode commits as it goes, so a lost answer
        // here is a lost commit - see inDoubt.
        long touched;
        try {
            touched = runBatch(values);
        } catch (SQLException failure) {
            throw inDoubt(failure, null);
        }
        for (int i = 0; i < counts.length; i++) {
            counts[i] = touched == counts.length ? 1 : Statement.SUCCESS_NO_INFO;
        }
        return counts;
    }

    private long runBatch(List<Object[]> values) throws SQLException {
        checkOpen();
        return runArray(sql, parameters, values.size(), row -> parameters.setAll(values.get(row)));
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
        checkOpen();
        return space.seclume.internal.jdbc.PlaceholderMetaData.of(parameterCount);
    }

    // Streams, Blob and Clob as parameters: ParameterSetters reads them and
    // sends the value - the rule this driver had first, now shared by all four.

    /**
     * A {@code ROWID} as a parameter - its printed form, which Oracle turns
     * back into an address itself, as it does for {@code where rowid = '...'}.
     */
    @Override
    public void setRowId(int index, java.sql.RowId value) throws SQLException {
        setString(index, value == null ? null : value.toString());
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
                space.seclume.QueryFingerprint.Dialect.ORACLE);
    }


    @Override
    public void setSensitive(int parameterIndex, java.lang.foreign.MemorySegment value)
            throws SQLException {
        setParameter(parameterIndex, new space.seclume.internal.jdbc.NativeValue(value));
    }

}
