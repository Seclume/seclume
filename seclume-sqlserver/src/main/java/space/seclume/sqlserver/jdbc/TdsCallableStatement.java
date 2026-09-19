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
        throw new java.sql.SQLFeatureNotSupportedException(
                "seclume does not read the parameter descriptions the server sends - it "
                + "encodes every parameter from its Java type instead");
    }

    @Override
    public void addBatch() throws SQLException {
        throw new java.sql.SQLFeatureNotSupportedException(
                "a call cannot be batched - its output parameters belong to one execution");
    }

    // ---- executing ---------------------------------------------------------

    @Override
    public boolean execute() throws SQLException {
        checkOpen();
        List<Object> bound = new ArrayList<>(call.parameters());
        String batch = buildBatch(bound);
        try (PreparedStatement statement = connection.prepareStatement(batch)) {
            for (int i = 0; i < bound.size(); i++) {
                statement.setObject(i + 1, bound.get(i));
            }
            statement.execute();
            readOutputs(statement);
        }
        return false;                         // the outputs are not a result the caller asked for
    }

    @Override
    public int executeUpdate() throws SQLException {
        execute();
        return 0;
    }

    @Override
    public ResultSet executeQuery() throws SQLException {
        throw new SQLException("this call is run with execute() and its outputs read with the "
                + "getters - a procedure's own result set is not carried through yet");
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

    /** The row the trailing select produced, in the order the outputs were declared. */
    private void readOutputs(PreparedStatement statement) throws SQLException {
        if (outputs.isEmpty()) {
            return;
        }
        try (ResultSet result = statement.getResultSet()) {
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
