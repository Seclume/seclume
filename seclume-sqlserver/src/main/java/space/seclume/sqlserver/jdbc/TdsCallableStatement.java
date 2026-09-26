package space.seclume.sqlserver.jdbc;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import space.seclume.internal.jdbc.CallSyntax;
import space.seclume.internal.jdbc.OutParameters;
import space.seclume.internal.jdbc.ParameterNames;
import space.seclume.internal.jdbc.ParameterSetters;

/**
 * {@code {call p(?, ?)}} on SQL Server, as one batch.
 *
 * <p>T-SQL can declare a variable, pass it to a procedure as
 * {@code OUTPUT} and select it back, all in a single statement:
 *
 * <pre>
 * declare @zl2 int;
 * exec p @P0, @zl2 output;
 * select @zl2
 * </pre>
 *
 * <p>So a call is one round trip and needs nothing of the protocol that is
 * not already here: the {@code IN} parameters are bound the way any prepared
 * statement binds them, and the outputs arrive as an ordinary result row.
 *
 * <p><b>The alternative, and why not.</b> TDS can call a procedure as an RPC
 * with parameters marked by-reference, and the server then answers with
 * {@code RETURNVALUE} tokens - no declared types to get right. This driver
 * reads those tokens for exactly one thing today, the handle of a
 * server-side cursor, and only as an {@code int}; making them general means
 * taking the type description apart in the shared token parser. That is the
 * better road and it is not a small one, so the batch form comes first and
 * says what it costs: <b>the declared width comes from the registration, not
 * from the procedure</b>, so an output registered as {@code VARCHAR} is
 * declared {@code nvarchar(4000)} and a longer value would be cut. A caller
 * who needs more says so with {@code registerOutParameter(i, VARCHAR,
 * "nvarchar(max)")} - the type name is passed through as written.
 */
final class TdsCallableStatement extends TdsStatement implements ParameterSetters, OutParameters {

    private final CallSyntax call;
    private final Map<Integer, Object> inputs = new HashMap<>();
    private final List<Integer> outputs = new ArrayList<>(2);
    private final Map<Integer, String> declaredTypes = new HashMap<>();
    private final Map<Integer, Object> values = new HashMap<>();
    private boolean lastWasNull;
    /**
     * The statement the call actually ran as.
     *
     * <p>It stays open after {@link #execute}, because a procedure's own
     * result sets live in it and the caller has not read them yet. Closed by
     * the next execution and by {@link #close}.
     */
    private TdsStatement run;

    TdsCallableStatement(TdsConnection connection, CallSyntax call) {
        super(connection);
        this.call = call;
    }

    // ---- input and output -------------------------------------------------

    @Override
    public void setParameter(int index, Object value) throws SQLException {
        checkOpen();
        if (index < 1) {
            throw new SQLException("parameter indexes start at 1, got " + index);
        }
        inputs.put(index, value);
    }

    @Override
    public void registerOut(int index, int sqlType, int scale, String typeName)
            throws SQLException {
        checkOpen();
        if (index < 1) {
            throw new SQLException("parameter indexes start at 1, got " + index);
        }
        if (!outputs.contains(index)) {
            outputs.add(index);
            outputs.sort(Integer::compareTo);
        }
        declaredTypes.put(index, typeName != null ? typeName : tsqlType(sqlType, scale));
    }

    @Override
    public Object outValue(int index) throws SQLException {
        checkOpen();
        if (!outputs.contains(index)) {
            throw new SQLException("parameter " + index + " was not registered as an output - "
                    + "call registerOutParameter before the call");
        }
        if (!values.containsKey(index)) {
            throw new SQLException("the call has not run yet, so parameter " + index
                    + " has no value");
        }
        Object value = values.get(index);
        lastWasNull = value == null;
        return value;
    }

    @Override
    public boolean lastWasNull() {
        return lastWasNull;
    }

    // ---- parameters by name ------------------------------------------------

    /**
     * The catalog question, asked once per statement.
     *
     * <p>SQL Server does not overload procedures, so the specific name is the
     * procedure's own and stands for one signature. Position 0 is a scalar
     * function's return value, which JDBC counts as parameter 1 by itself.
     * The names the catalog holds carry the {@code @} SQL Server writes them
     * with; {@code ParameterNames} strips it from either side, so an
     * application may pass the name with it or without.
     */
    private static final String PARAMETER_QUERY = """
            select p.specific_name, p.parameter_name, p.ordinal_position
              from information_schema.parameters p
             where lower(p.specific_name) = lower(?)
               and (%s)
               and p.ordinal_position > 0
             order by p.ordinal_position""";

    private ParameterNames names;

    @Override
    public int indexOf(String parameterName) throws SQLException {
        checkOpen();
        if (names == null) {
            names = loadNames();
        }
        return names.indexOf(parameterName);
    }

    private ParameterNames loadNames() throws SQLException {
        String schema = null;
        String routine = call.name();
        int dot = routine.lastIndexOf('.');
        if (dot >= 0) {
            schema = routine.substring(0, dot);
            routine = routine.substring(dot + 1);
        }
        String sql = PARAMETER_QUERY.formatted(
                schema == null ? "1 = 1" : "lower(p.specific_schema) = lower(?)");
        int arguments = call.parameters() - (call.returnsValue() ? 1 : 0);
        try (java.sql.PreparedStatement ask = connection.prepareStatement(sql)) {
            ask.setString(1, unquoted(routine));
            if (schema != null) {
                ask.setString(2, unquoted(schema));
            }
            try (java.sql.ResultSet rows = ask.executeQuery()) {
                return ParameterNames.fromCatalog(rows, arguments, call.returnsValue());
            }
        }
    }

    /** A quoted identifier stands for itself; the brackets are not part of the name. */
    private static String unquoted(String identifier) {
        String text = identifier.trim();
        return text.length() > 1 && text.startsWith("[") && text.endsWith("]")
                ? text.substring(1, text.length() - 1)
                : text;
    }

    @Override
    public void clearParameters() throws SQLException {
        checkOpen();
        inputs.clear();
    }

    @Override
    public java.sql.ResultSetMetaData getMetaData() throws SQLException {
        checkOpen();
        ResultSet result = currentResultSet();
        return result == null ? null : result.getMetaData();
    }

    @Override
    public java.sql.ParameterMetaData getParameterMetaData() throws SQLException {
        checkOpen();
        return space.seclume.internal.jdbc.PlaceholderMetaData.ofCall(call.totalParameters());
    }

    @Override
    public void addBatch() throws SQLException {
        throw new java.sql.SQLFeatureNotSupportedException(
                "a call cannot be batched - its output parameters belong to one execution");
    }

    // ---- executing ---------------------------------------------------------

    /**
     * Runs the call and leaves its own result sets where the caller can read
     * them.
     *
     * <p>A procedure on SQL Server has no cursor parameter: it selects, and
     * the rows come back as results of the batch. The batch this class builds
     * appends one select of its own to read the output parameters, so the
     * <b>last</b> result belongs to the driver - it is taken away here, and
     * everything before it is the procedure's and is handed on unchanged.
     */
    @Override
    public boolean execute() throws SQLException {
        checkOpen();
        closeRun();
        List<Object> bound = new ArrayList<>(call.parameters());
        String batch = buildBatch(bound);
        TdsStatement statement = (TdsStatement) connection.prepareStatement(batch);
        boolean kept = false;
        try {
            PreparedStatement prepared = (PreparedStatement) statement;
            for (int i = 0; i < bound.size(); i++) {
                prepared.setObject(i + 1, bound.get(i));
            }
            prepared.execute();
            readOutputs(statement);
            statement.positionAtFirstResult();
            run = statement;
            kept = true;
            return statement.getResultSet() != null;
        } finally {
            if (!kept) {
                statement.close();
            }
        }
    }

    @Override
    public int executeUpdate() throws SQLException {
        execute();
        return run == null ? 0 : Math.max(run.getUpdateCount(), 0);
    }

    @Override
    public ResultSet executeQuery() throws SQLException {
        if (!execute()) {
            throw new SQLException("the procedure " + call.name() + " returned no rows - "
                    + "run it with execute() and read its output parameters with the getters");
        }
        return run.getResultSet();
    }

    // ---- the procedure's own results ---------------------------------------

    @Override
    public ResultSet getResultSet() throws SQLException {
        checkOpen();
        return run == null ? null : run.getResultSet();
    }

    @Override
    public boolean getMoreResults() throws SQLException {
        checkOpen();
        return run != null && run.getMoreResults();
    }

    @Override
    public boolean getMoreResults(int current) throws SQLException {
        return getMoreResults();
    }

    @Override
    public int getUpdateCount() throws SQLException {
        checkOpen();
        return run == null ? -1 : run.getUpdateCount();
    }

    @Override
    public void close() {
        closeRun();
        super.close();
    }

    private void closeRun() {
        if (run != null) {
            run.close();
            run = null;
        }
    }

    /**
     * The whole call as one statement, collecting what has to be bound.
     *
     * <p>A variable is declared for each output and assigned first when the
     * caller also gave it a value - that is what makes an {@code INOUT} an
     * {@code INOUT} rather than an empty slot.
     */
    private String buildBatch(List<Object> bound) {
        StringBuilder sql = new StringBuilder(128);
        for (int index : outputs) {
            sql.append("declare ").append(variable(index)).append(' ')
                    .append(declaredTypes.getOrDefault(index, "sql_variant")).append("; ");
        }
        for (int index : outputs) {
            if (inputs.containsKey(index)) {
                sql.append("set ").append(variable(index)).append(" = ?; ");
                bound.add(inputs.get(index));
            }
        }

        String arguments = call.argumentsWith(placeholder -> {
            int index = call.returnsValue() ? placeholder + 1 : placeholder;
            if (outputs.contains(index)) {
                return variable(index) + " output";
            }
            bound.add(inputs.get(index));
            return "?";
        });

        if (call.returnsValue()) {
            // A function is selected, not executed; the return value is the
            // first thing selected back.
            sql.append("select ").append(call.name()).append('(').append(arguments).append(')');
            for (int index : outputs) {
                if (index != 1) {
                    sql.append(", ").append(variable(index));
                }
            }
            return sql.toString();
        }

        sql.append("exec ").append(call.name());
        if (!arguments.isEmpty()) {
            sql.append(' ').append(arguments);
        }
        if (!outputs.isEmpty()) {
            sql.append("; select ");
            for (int i = 0; i < outputs.size(); i++) {
                sql.append(i == 0 ? "" : ", ").append(variable(outputs.get(i)));
            }
        }
        return sql.toString();
    }

    /**
     * The row the trailing select produced, in the order the outputs were
     * declared.
     *
     * <p>It is the answer's last result, not its first: anything the
     * procedure selected itself came before it.
     */
    private void readOutputs(TdsStatement statement) throws SQLException {
        if (outputs.isEmpty()) {
            return;
        }
        try (ResultSet result = statement.takeLastResult()) {
            if (result == null || !result.next()) {
                throw new SQLException("the call did not return its output parameters - "
                        + "the procedure may not have the OUTPUT parameters it was called with");
            }
            for (int i = 0; i < outputs.size(); i++) {
                values.put(outputs.get(i), result.getObject(i + 1));
            }
        }
    }

    private static String variable(int index) {
        return "@zl_out" + index;
    }

    /**
     * A T-SQL type wide enough for what was registered.
     *
     * <p>Deliberately generous rather than exact: the registration says
     * {@code VARCHAR} and not how long, so the declaration has to be wide
     * enough for anything a procedure is likely to put there. Whoever knows
     * better passes the type name and gets it through unchanged.
     */
    private static String tsqlType(int sqlType, int scale) {
        return switch (sqlType) {
            case Types.BIT, Types.BOOLEAN -> "bit";
            case Types.TINYINT -> "tinyint";
            case Types.SMALLINT -> "smallint";
            case Types.INTEGER -> "int";
            case Types.BIGINT -> "bigint";
            case Types.REAL -> "real";
            case Types.FLOAT, Types.DOUBLE -> "float";
            case Types.NUMERIC, Types.DECIMAL ->
                    "decimal(38, " + (scale < 0 ? 0 : Math.min(scale, 38)) + ")";
            case Types.DATE -> "date";
            case Types.TIME -> "time";
            case Types.TIMESTAMP -> "datetime2";
            case Types.BINARY, Types.VARBINARY, Types.LONGVARBINARY -> "varbinary(8000)";
            case Types.CHAR, Types.VARCHAR, Types.LONGVARCHAR,
                 Types.NCHAR, Types.NVARCHAR, Types.LONGNVARCHAR -> "nvarchar(4000)";
            default -> "sql_variant";
        };
    }
}
