package space.seclume.mysql.jdbc;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import space.seclume.internal.jdbc.CallSyntax;
import space.seclume.internal.jdbc.OutParameters;
import space.seclume.internal.jdbc.ParameterNames;
import space.seclume.internal.jdbc.ParameterSetters;

/**
 * {@code {call p(?, ?)}} on MySQL, through session variables.
 *
 * <p>MySQL will not simply hand an {@code OUT} parameter back on a bind:
 * what it accepts in that position of a {@code CALL} is a user variable, and
 * the value is read afterwards with a {@code SELECT}. So a call runs as up
 * to three statements:
 *
 * <pre>
 * SET @zl_c1_2 = ?            -- only for INOUT, and only what was bound
 * CALL p(?, @zl_c1_2)         -- IN parameters bound, outputs as variables
 * SELECT @zl_c1_2             -- the values, in the order registered
 * </pre>
 *
 * <p>That is what Connector/J does, and the reason is the protocol rather
 * than a preference: the binary protocol can return output parameters in a
 * result of their own, but only for a statement the server prepared as a
 * procedure call, and the flag that marks such a result is easy to read
 * wrongly. Three statements against a server on the same machine cost less
 * than a subtle misreading.
 *
 * <p><b>The outputs are read back inside {@code execute()}</b>, not when a
 * getter asks for them. That is what makes two calls on one connection safe
 * from each other: the value is taken before anything else can run. It was
 * checked the other way round too - with the variable names shared, the
 * test still passes, because the eager read gets there first.
 *
 * <p>The names still carry the statement's own number
 * ({@code @zl_c<statement>_<parameter>}), because user variables live on the
 * connection and a procedure may well use one of its own. That is cheap
 * insurance against a collision this project has not had to debug, rather
 * than a fix for one it has.
 */
final class MyCallableStatement extends MyStatement implements ParameterSetters, OutParameters {

    private static final AtomicLong STATEMENTS = new AtomicLong();

    private final CallSyntax call;
    private final String prefix;
    /** What the caller set, by its own parameter number. */
    private final Map<Integer, Object> inputs = new HashMap<>();
    /** Registered outputs in ascending order - the order they are selected back in. */
    private final List<Integer> outputs = new ArrayList<>(2);
    private final Map<Integer, Object> values = new HashMap<>();
    private boolean lastWasNull;

    MyCallableStatement(MyConnection connection, CallSyntax call) {
        super(connection);
        this.call = call;
        this.prefix = "@zl_c" + STATEMENTS.incrementAndGet() + "_";
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
     * <p>MySQL does not overload routines, so the routine's own name is the
     * key {@link ParameterNames#fromCatalog} needs. Position 0 is a
     * function's return value, which JDBC counts as parameter 1 by itself,
     * and is therefore left out. Where the call named no schema the current
     * one is meant - {@code database()}, not every schema on the server,
     * because two of them may well hold a procedure of the same name.
     */
    private static final String PARAMETER_QUERY = """
            select p.specific_name, p.parameter_name, p.ordinal_position
              from information_schema.parameters p
             where lower(p.specific_name) = lower(?)
               and lower(p.specific_schema) = lower(%s)
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
        // Two shapes rather than one with a null bind: a placeholder that is
        // only ever compared against NULL has no type MySQL can infer.
        String sql = PARAMETER_QUERY.formatted(schema == null ? "database()" : "?");
        int arguments = call.parameters() - (call.returnsValue() ? 1 : 0);
        try (PreparedStatement ask = connection.prepareStatement(sql)) {
            ask.setString(1, unquoted(routine));
            if (schema != null) {
                ask.setString(2, unquoted(schema));
            }
            try (ResultSet rows = ask.executeQuery()) {
                return ParameterNames.fromCatalog(rows, arguments, call.returnsValue());
            }
        }
    }

    /** A quoted identifier stands for itself; the backticks are not part of the name. */
    private static String unquoted(String identifier) {
        String text = identifier.trim();
        return text.length() > 1 && text.startsWith("`") && text.endsWith("`")
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
        throw new java.sql.SQLFeatureNotSupportedException(
                "seclume does not read the parameter descriptions the server sends - it "
                + "encodes every parameter from its Java type instead");
    }

    /**
     * Refused: a batch of calls would have to keep one set of output
     * variables per call and hand them all back, and nothing asks for it.
     * Better said than half done.
     */
    @Override
    public void addBatch() throws SQLException {
        throw new java.sql.SQLFeatureNotSupportedException(
                "a call cannot be batched - its output parameters belong to one execution");
    }

    // ---- executing ---------------------------------------------------------

    @Override
    public boolean execute() throws SQLException {
        checkOpen();
        assignInputsToVariables();
        boolean hasResult = runTheCall();
        readVariablesBack();
        return hasResult;
    }

    @Override
    public int executeUpdate() throws SQLException {
        execute();
        return Math.max(getUpdateCount(), 0);
    }

    @Override
    public ResultSet executeQuery() throws SQLException {
        if (!execute() || currentResultSet() == null) {
            throw new SQLException("the call returned no rows: " + call.name()
                    + " - use execute() and read its output parameters");
        }
        return currentResultSet();
    }

    /** {@code SET @var = ?} for every output the caller also gave a value to. */
    private void assignInputsToVariables() throws SQLException {
        List<Integer> withValues = new ArrayList<>(outputs.size());
        for (int index : outputs) {
            if (inputs.containsKey(index)) {
                withValues.add(index);
            }
        }
        if (withValues.isEmpty()) {
            return;
        }
        StringBuilder sql = new StringBuilder("set ");
        for (int i = 0; i < withValues.size(); i++) {
            sql.append(i == 0 ? "" : ", ").append(prefix).append(withValues.get(i)).append(" = ?");
        }
        try (PreparedStatement set = connection.prepareStatement(sql.toString())) {
            for (int i = 0; i < withValues.size(); i++) {
                set.setObject(i + 1, inputs.get(withValues.get(i)));
            }
            set.execute();
        }
    }

    /** The call itself: outputs as variables, everything else bound. */
    private boolean runTheCall() throws SQLException {
        List<Object> bound = new ArrayList<>(call.parameters());
        String arguments = call.argumentsWith(placeholder -> {
            int index = call.returnsValue() ? placeholder + 1 : placeholder;
            if (outputs.contains(index)) {
                return prefix + index;
            }
            bound.add(inputs.get(index));
            return "?";
        });

        String sql = call.returnsValue()
                ? "select " + call.name() + "(" + arguments + ")"
                : "call " + call.name() + "(" + arguments + ")";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < bound.size(); i++) {
                statement.setObject(i + 1, bound.get(i));
            }
            boolean hasResult = statement.execute();
            if (call.returnsValue()) {
                // A function's value is the one column of the one row, and it
                // is an output like any other - parameter 1, by definition.
                try (ResultSet result = statement.getResultSet()) {
                    values.put(1, result != null && result.next() ? result.getObject(1) : null);
                }
                return false;
            }
            return hasResult;
        }
    }

    /** {@code SELECT @a, @b} - the outputs, in the order they were registered. */
    private void readVariablesBack() throws SQLException {
        List<Integer> wanted = new ArrayList<>(outputs);
        if (call.returnsValue()) {
            wanted.remove(Integer.valueOf(1));   // already taken from the function's result
        }
        if (wanted.isEmpty()) {
            return;
        }
        StringBuilder sql = new StringBuilder("select ");
        for (int i = 0; i < wanted.size(); i++) {
            sql.append(i == 0 ? "" : ", ").append(prefix).append(wanted.get(i));
        }
        try (PreparedStatement select = connection.prepareStatement(sql.toString());
                ResultSet result = select.executeQuery()) {
            if (result.next()) {
                for (int i = 0; i < wanted.size(); i++) {
                    values.put(wanted.get(i), result.getObject(i + 1));
                }
            }
        }
    }
}
