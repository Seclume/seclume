package space.seclume.postgresql.jdbc;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import space.seclume.internal.jdbc.CallSyntax;
import space.seclume.internal.jdbc.OutParameters;
import space.seclume.postgresql.PgSession;

/**
 * {@code {call p(?, ?)}} on PostgreSQL.
 *
 * <p>PostgreSQL has no separate call protocol, and does not need one: a
 * procedure is invoked with {@code CALL} and <b>hands its output back as a
 * row</b>, one column per {@code OUT} or {@code INOUT} parameter, in
 * declaration order. A function is a query. So this is an ordinary prepared
 * statement with the escape syntax translated in front of it and that one
 * row read out behind it - which is why it extends
 * {@link PgPreparedStatement} rather than repeating parse, bind and execute.
 *
 * <ul>
 *   <li><code>{call p(?, ?)}</code> becomes {@code CALL p($1, $2)};
 *   <li><code>{? = call f(?)}</code> becomes {@code SELECT * FROM f($1)},
 *       and the return value is the first column.
 * </ul>
 *
 * <p><b>The renumbering is the part to be careful with.</b> In the second
 * form the caller counts the return value as parameter 1 and the argument as
 * parameter 2, while the statement that goes to the server has a single
 * placeholder. Every index therefore shifts by one on the way down, and back
 * on the way out. Getting that wrong binds the argument into nothing and
 * reads the result from a column that is not there.
 *
 * <p><b>A pure {@code OUT} parameter still has to be bound.</b> PostgreSQL
 * wants an argument in that position; NULL is what belongs there. It is
 * filled in at execution time and only where the caller bound nothing, so an
 * {@code INOUT} keeps the value it was given.
 */
final class PgCallableStatement extends PgPreparedStatement implements OutParameters {

    private final CallSyntax call;
    /** Registered outputs in ascending order - the order the row's columns arrive in. */
    private final List<Integer> outputs = new ArrayList<>(2);
    private Object[] values = new Object[0];
    private boolean lastWasNull;

    PgCallableStatement(PgConnection connection, CallSyntax call, String name,
            List<PgSession.Field> cached) throws SQLException {
        super(connection, statementFor(call), name, cached);
        this.call = call;
    }

    /** What actually goes to the server - see the class comment. */
    static String statementFor(CallSyntax call) {
        String arguments = "(" + call.arguments() + ")";
        return call.returnsValue()
                ? "select * from " + call.name() + arguments
                : "call " + call.name() + arguments;
    }

    // ---- the indexes ------------------------------------------------------

    /** The placeholder a caller's parameter number stands for. */
    private int wireIndex(int index) throws SQLException {
        int shifted = call.returnsValue() ? index - 1 : index;
        if (shifted < 1) {
            throw new SQLException("parameter 1 of this call is its return value - it is read "
                    + "with a getter after the call, not set before it");
        }
        return shifted;
    }

    @Override
    void set(int index, Object value) throws SQLException {
        super.set(wireIndex(index), value);
    }

    // ---- outputs ----------------------------------------------------------

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
        int at = outputs.indexOf(index);
        if (at < 0) {
            throw new SQLException("parameter " + index + " was not registered as an output - "
                    + "call registerOutParameter before the call, or the server never sent it");
        }
        if (at >= values.length) {
            throw new SQLException("the call returned " + values.length + " values and "
                    + "parameter " + index + " is the " + (at + 1) + "th output - the procedure's "
                    + "signature and the registration do not agree");
        }
        Object value = values[at];
        lastWasNull = value == null;
        return value;
    }

    @Override
    public boolean lastWasNull() {
        return lastWasNull;
    }

    // ---- executing ---------------------------------------------------------

    @Override
    public boolean execute() throws SQLException {
        bindUnsetOutputs();
        boolean hasResult = super.execute();
        takeOutputs();
        // The row carrying the outputs is this call's own bookkeeping, not a
        // result the caller asked for. A procedure that also selects something
        // is a different matter, and PostgreSQL does not do that through CALL.
        return hasResult && outputs.isEmpty();
    }

    @Override
    public int executeUpdate() throws SQLException {
        execute();
        return Math.max(getUpdateCount(), 0);
    }

    @Override
    public ResultSet executeQuery() throws SQLException {
        if (!outputs.isEmpty()) {
            throw new SQLException("this call has output parameters - run it with execute() and "
                    + "read them with the getters");
        }
        return super.executeQuery();
    }

    /**
     * NULL for every output the caller bound nothing to. PostgreSQL wants an
     * argument in that position, and an unbound trailing parameter would not
     * be sent at all.
     */
    private void bindUnsetOutputs() throws SQLException {
        for (int index : outputs) {
            if (call.returnsValue() && index == 1) {
                continue;                     // the return value has no placeholder to bind
            }
            int wire = wireIndex(index);
            if (parameters().get(wire) == null) {
                super.set(wire, null);
            }
        }
    }

    /** Takes the one row the call answered with, then forgets it. */
    private void takeOutputs() throws SQLException {
        if (outputs.isEmpty()) {
            return;
        }
        ResultSet result = currentResultSet();
        if (result == null) {
            values = new Object[0];
            return;
        }
        List<Object> read = new ArrayList<>(outputs.size());
        if (result.next()) {
            int columns = result.getMetaData().getColumnCount();
            for (int column = 1; column <= columns; column++) {
                read.add(result.getObject(column));
            }
        }
        values = read.toArray();
    }
}
