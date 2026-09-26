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
final class TdsPreparedStatement extends TdsStatement implements ParameterSetters,
        space.seclume.SensitiveParameters {

    private final String originalSql;
    private final String sql;
    private final int parameterCount;
    private final TdsParameters parameters = new TdsParameters();
    /**
     * The handle the server gave this statement, once it has one.
     *
     * <p>Kept for the statement's lifetime, not per batch: the first batch
     * pays one round trip to compile, every batch after it sends handles only.
     * Given back in {@link #close()}.
     */
    private final TdsSession.Prepared prepared = new TdsSession.Prepared();
    private List<Object[]> batch;
    private final boolean wantsGeneratedKeys;

    TdsPreparedStatement(TdsConnection connection, String sql) throws SQLException {
        this(connection, sql, false);
    }

    /**
     * @param wantsGeneratedKeys whether the caller asked for the key an
     *                           identity column hands out - see
     *                           {@link #keyCarryingSql}
     */
    TdsPreparedStatement(TdsConnection connection, String sql, boolean wantsGeneratedKeys)
            throws SQLException {
        super(connection);
        this.originalSql = sql;
        TdsSqlRewriter.Rewritten rewritten = TdsSqlRewriter.rewrite(sql);
        this.sql = rewritten.sql();
        this.parameterCount = rewritten.parameters();
        this.wantsGeneratedKeys = wantsGeneratedKeys;
    }

    /**
     * The statement with its own {@code scope_identity()} behind it.
     *
     * <p><b>Why it has to travel with the statement rather than follow it.</b>
     * A prepared statement runs through {@code sp_executesql}, which is a
     * scope of its own. {@code SCOPE_IDENTITY()} asked afterwards, in a batch
     * of its own, therefore does not see that insert at all - it reports
     * whatever the outer scope last inserted, which is the previous statement's
     * key or nothing. Measured: inserting through a {@code Statement} and then
     * through a {@code PreparedStatement} gave rows 1 and 2, and asking
     * afterwards returned 1 both times. A wrong key, not an error, which is
     * the worst shape a bug can take here - so the select rides along inside
     * the same call, which is what the vendor driver does too.
     */
    private static String keyCarryingSql(String sql) {
        return sql + ";select scope_identity() as GENERATED_KEY";
    }

    /** Lists bound to {@code in (?)}, by parameter index - see InLists; null for none. */
    private space.seclume.internal.jdbc.InLists.Bound[] lists;
    /** The statement text the lists were last applied to, and what it became. */
    private String listSource;
    private String listSql;
    /** The compiled statement for the list form - a different text needs its own. */
    private TdsSession.Prepared listPrepared;

    /** The text to send: the statement's own, or its form for the bound lists. */
    private String currentSql() throws SQLException {
        if (!space.seclume.internal.jdbc.InLists.any(lists)) {
            return sql;
        }
        String applied = space.seclume.internal.jdbc.InLists.apply(originalSql, lists,
                space.seclume.internal.jdbc.InLists.Dialect.SQLSERVER);
        if (!applied.equals(listSource)) {
            listSource = applied;
            listSql = TdsSqlRewriter.rewrite(applied).sql();
            listPrepared = new TdsSession.Prepared();
        }
        return listSql;
    }

    // ---- executing -------------------------------------------------------

    @Override
    public boolean execute() throws SQLException {
        run();
        return currentResultSet() != null;
    }

    @Override
    public ResultSet executeQuery() throws SQLException {
        lazyWanted = true;
        try {
            run();
        } finally {
            lazyWanted = false;
        }
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
        TdsSession session = connection.session();
        if (session.isPipelining() && !wantsGeneratedKeys && blockSize() <= 0) {
            // Inside a pipeline block this is buffered rather than sent - see
            // Pipeline. Generated keys and cursors are excluded because both
            // need an answer of their own, and a block that quietly sent them
            // anyway would be a block that sometimes saves a round trip and
            // sometimes does not, which is worse than one that never does.
            if (parameters.count() < parameterCount) {
                throw new SQLException("the statement has " + parameterCount
                        + " parameters but only " + parameters.count() + " were set");
            }
            String text = currentSql();
            parameters.preferVarchar(VarcharParameters.of(connection, text, parameters));
            return session.pipelineExecute(text == sql ? prepared : listPrepared, text,
                    parameters);
        }
        run();
        return Math.max(getLargeUpdateCount(), 0);
    }

    private void run() throws SQLException {
        underDeadline(sql, this::runNow);
    }

    private void runNow() throws SQLException {
        checkOpen();
        if (parameters.count() < parameterCount) {
            throw new SQLException("the statement has " + parameterCount
                    + " parameters but only " + parameters.count() + " were set");
        }
        TdsSession session = connection.session();
        String sql = currentSql();
        parameters.preferVarchar(VarcharParameters.of(connection, sql, parameters));
        String declaration = parameters.declaration();
        // A fetch size means the server keeps the rows and hands them out in
        // blocks - see TdsStatement#openCursor. Only for a statement that
        // returns rows: SQL Server opens a cursor over nothing else (error
        // 16938), and a fetch size a framework sets on every statement made
        // each insert and update fail with it.
        if (blockSize() > 0 && !wantsGeneratedKeys && returnsRows(sql)) {
            openCursor(session, sql, declaration, parameters);
            return;
        }
        capturingGeneratedKeys = wantsGeneratedKeys;
        String statement = wantsGeneratedKeys ? keyCarryingSql(sql) : sql;
        collect(session, handler -> session.rpc(statement, declaration, parameters, handler));
    }

    /**
     * Whether a statement is a query, by its first word after comments and
     * spaces - {@code select}, or {@code with} for a common table expression.
     *
     * <p>Anything else runs as before and reads its result whole, which is
     * always correct and only costs memory for a result that is large.
     */
    static boolean returnsRows(String text) {
        int at = 0;
        int length = text.length();
        while (at < length) {
            char c = text.charAt(at);
            if (Character.isWhitespace(c) || c == '(') {
                at++;
            } else if (text.startsWith("--", at)) {
                int end = text.indexOf('\n', at);
                at = end < 0 ? length : end + 1;
            } else if (text.startsWith("/*", at)) {
                int end = text.indexOf("*/", at + 2);
                at = end < 0 ? length : end + 2;
            } else {
                break;
            }
        }
        return word(text, at, "select") || word(text, at, "with");
    }

    private static boolean word(String text, int at, String keyword) {
        int end = at + keyword.length();
        return text.regionMatches(true, at, keyword, 0, keyword.length())
                && (end == text.length() || !Character.isLetterOrDigit(text.charAt(end)));
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
                value, space.seclume.internal.jdbc.InLists.Dialect.SQLSERVER);
        lists = space.seclume.internal.jdbc.InLists.note(lists, index, list);
        parameters.set(index, list == null ? value : list.payload());
    }

    /**
     * A null with its type, because SQL Server declares every parameter.
     *
     * <p>The shared default throws the type away, which is right where the
     * server infers it from the statement. An RPC does not: the parameter
     * list says {@code @P1 nvarchar(1)}, and the server then refuses to put
     * that into a {@code varbinary} column.
     */
    @Override
    public void setNull(int index, int sqlType) throws SQLException {
        setParameter(index, new space.seclume.sqlserver.tds
                .TdsParameters.TypedNull(sqlType));
    }

    @Override
    public void setNull(int index, int sqlType, String typeName) throws SQLException {
        setNull(index, sqlType);
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
        // The first row decides which parameters are compared with varchar
        // columns; the answer is about the statement, not the values.
        parameters.clear();
        Object[] first = rows.get(0);
        for (int p = 0; p < first.length; p++) {
            parameters.set(p + 1, first[p]);
        }
        parameters.preferVarchar(VarcharParameters.of(connection, sql, parameters));
        // A batch in auto-commit mode commits as it goes, so a lost answer
        // here is a lost commit - see inDoubt.
        try {
            return session.rpcBatch(prepared, sql, parameters, rows.size(), row -> {
                Object[] values = rows.get(row);
                parameters.clear();
                for (int p = 0; p < values.length; p++) {
                    parameters.set(p + 1, values[p]);
                }
            });
        } catch (SQLException failure) {
            throw inDoubt(failure, null);
        }
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

    /**
     * Closes the statement and gives its compiled handle back.
     *
     * <p>One round trip, and the alternative is worse: a pooled connection
     * that prepares and never unprepares fills the server's plan cache with
     * statements nobody will run again.
     */
    @Override
    public void close() {
        if (prepared.isPrepared()) {
            try {
                connection.session().unprepare(prepared.handle());
            } catch (SQLException ignored) {
                // A handle that cannot be given back is not worth failing a
                // close over - the connection closing takes it with it. And
                // close() does not throw here, because the one in TdsStatement
                // does not either.
            }
        }
        super.close();
    }

    @Override
    public void addBatch(String otherSql) throws SQLException {
        throw new SQLException("this is a prepared statement - use addBatch() without SQL");
    }

    /**
     * The key this insert produced - captured from the statement's own call,
     * never asked for afterwards.
     *
     * <p>Empty rather than wrong when the caller never asked for keys:
     * {@code prepareStatement(sql)} sends no {@code scope_identity()}, and
     * inventing one here would read another statement's identity. JDBC allows
     * an empty result for exactly this case.
     */
    @Override
    public ResultSet getGeneratedKeys() throws SQLException {
        checkOpen();
        ResultSet keys = capturedGeneratedKeys();
        if (keys != null) {
            return keys;
        }
        if (wantsGeneratedKeys) {
            throw new SQLException("the statement asked for generated keys and the server "
                    + "returned none - it inserted into no identity column");
        }
        throw new SQLException("this statement was not prepared for generated keys - "
                + "use prepareStatement(sql, Statement.RETURN_GENERATED_KEYS), because the key "
                + "has to be asked for inside the same call and cannot be fetched afterwards");
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
        checkOpen();
        return space.seclume.internal.jdbc.PlaceholderMetaData.ofText(originalSql);
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
                space.seclume.QueryFingerprint.Dialect.SQLSERVER);
    }


    @Override
    public void setSensitive(int parameterIndex, java.lang.foreign.MemorySegment value)
            throws SQLException {
        setParameter(parameterIndex, new space.seclume.internal.jdbc.NativeValue(value));
    }

}
