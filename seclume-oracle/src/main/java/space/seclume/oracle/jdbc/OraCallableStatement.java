package space.seclume.oracle.jdbc;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
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
import space.seclume.oracle.net.OracleColumn;
import space.seclume.oracle.net.OracleNumber;
import space.seclume.oracle.net.TtcBinds;

/**
 * {@code {call p(?, ?)}} on Oracle, as an anonymous PL/SQL block.
 *
 * <p>Oracle is the only one of the four where a call is neither a statement
 * of its own nor a translation into one: {@code begin p(:1, :2); end;} is
 * sent like any other statement, and an {@code OUT} parameter is a
 * <b>bind the server writes into</b>. The values come back in front of the
 * answer, in the same {@code ROW_DATA} shape an
 * {@code insert ... returning ... into} uses - which is why that machinery
 * is what this builds on rather than something new.
 *
 * <p><b>What had to be added for it, and why each mattered.</b> Output binds
 * existed here, but only in the shape generated keys need:
 *
 * <ul>
 *   <li>they could only be <b>appended</b>, because a {@code returning}
 *       clause puts its binds at the end. A call's outputs sit wherever the
 *       caller wrote them, so {@link TtcBinds#setOutput} marks a chosen one;
 *   <li>they were always described as a <b>NUMBER</b>, which is all a
 *       generated key ever is. A {@code VARCHAR2} output described that way
 *       comes back as bytes that decode into nonsense rather than into an
 *       error, so the description now follows the registered type;
 *   <li>and what comes back was decoded as a number and nothing else. Here it
 *       is decoded by the type that was registered.
 * </ul>
 *
 * <p><b>An {@code IN OUT} is bound with its value</b>, not as an empty
 * output: the server writes back into it either way, and a placeholder would
 * throw away the half that goes in. The consequence to know is that its
 * buffer is then sized to the value that was sent, so a text parameter whose
 * procedure returns something longer than it was given will be refused by
 * the server rather than truncated.
 *
 * <p>A function is the same block with an assignment in it:
 * {@code begin :1 := f(:2); end;} - so its return value is simply the output
 * bind at position one, and nothing about the numbering shifts. That is one
 * thing Oracle makes easier than the other three.
 */
final class OraCallableStatement extends OraStatement
        implements ParameterSetters, OutParameters {

    private final CallSyntax call;
    private final Map<Integer, Object> inputs = new HashMap<>();
    /** Registered outputs in ascending order - the order they come back in. */
    private final List<Integer> outputs = new ArrayList<>(2);
    private final Map<Integer, Integer> registeredTypes = new HashMap<>();
    private final Map<Integer, Object> values = new HashMap<>();
    private boolean lastWasNull;

    OraCallableStatement(OraConnection connection, CallSyntax call) {
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
        registeredTypes.put(index, sqlType);
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
        TtcBinds binds = new TtcBinds();
        int total = call.totalParameters();
        for (int index = 1; index <= total; index++) {
            Object given = inputs.get(index);
            if (outputs.contains(index) && given == null) {
                binds.setOutput(index, oracleType(registeredTypes.getOrDefault(index,
                        Types.NUMERIC)));
            } else {
                // An IN OUT is bound with its value like any input - the
                // server knows from the procedure's own signature that it
                // writes back into it, and says so in the io vector of the
                // answer. Sending only a placeholder would lose the value
                // going in, which is half of what IN OUT means.
                binds.set(index, given);
            }
        }

        connection.session().expectReturning(outputs.size(), true);
        run(block(), binds);
        decodeOutputs(lastReturned());
        return false;                         // outputs are not a result the caller asked for
    }

    @Override
    public int executeUpdate() throws SQLException {
        execute();
        return 0;
    }

    @Override
    public ResultSet executeQuery() throws SQLException {
        throw new SQLException("this call is run with execute() and its outputs read with the "
                + "getters - a procedure's own cursor is not carried through yet");
    }

    /** {@code begin p(:1); end;}, or with the assignment a function needs. */
    private String block() {
        String arguments = call.argumentsWith(placeholder ->
                ":" + (call.returnsValue() ? placeholder + 1 : placeholder));
        String invocation = call.name() + (arguments.isEmpty() && call.parameters() == 0
                ? "" : "(" + arguments + ")");
        return call.returnsValue()
                ? "begin :1 := " + invocation + "; end;"
                : "begin " + invocation + "; end;";
    }

    /**
     * The bytes the server wrote back, read as what was registered.
     *
     * <p>They arrive in the order the output binds were described, which is
     * ascending by position - the same order {@link #outputs} holds.
     */
    private void decodeOutputs(List<byte[]> returned) throws SQLException {
        for (int i = 0; i < outputs.size(); i++) {
            int index = outputs.get(i);
            byte[] bytes = i < returned.size() ? returned.get(i) : new byte[0];
            values.put(index, bytes.length == 0 ? null
                    : decode(bytes, registeredTypes.getOrDefault(index, Types.NUMERIC)));
        }
    }

    private static Object decode(byte[] bytes, int sqlType) throws SQLException {
        return switch (sqlType) {
            case Types.CHAR, Types.VARCHAR, Types.LONGVARCHAR, Types.NCHAR, Types.NVARCHAR,
                 Types.LONGNVARCHAR ->
                    // seclume-allow: an output value, the same payload a ResultSet hands out
                    new String(bytes, StandardCharsets.UTF_8);
            case Types.BINARY, Types.VARBINARY, Types.LONGVARBINARY -> bytes;
            default -> number(bytes, sqlType);
        };
    }

    /** Oracle's own number format, read as whatever integer or decimal was asked for. */
    private static Object number(byte[] bytes, int sqlType) throws SQLException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment segment = arena.allocate(bytes.length);
            MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return switch (sqlType) {
                case Types.TINYINT, Types.SMALLINT, Types.INTEGER, Types.BIGINT ->
                        OracleNumber.toLong(segment, 0, bytes.length);
                case Types.REAL, Types.FLOAT, Types.DOUBLE ->
                        OracleNumber.toDouble(segment, 0, bytes.length);
                default -> new BigDecimal(OracleNumber.toText(segment, 0, bytes.length));
            };
        }
    }

    /** What the server should write, from what the caller registered. */
    private static int oracleType(int sqlType) {
        return switch (sqlType) {
            case Types.CHAR, Types.VARCHAR, Types.LONGVARCHAR, Types.NCHAR, Types.NVARCHAR,
                 Types.LONGNVARCHAR -> OracleColumn.TYPE_VARCHAR;
            case Types.DATE, Types.TIME, Types.TIMESTAMP -> OracleColumn.TYPE_DATE;
            case Types.BINARY, Types.VARBINARY, Types.LONGVARBINARY -> OracleColumn.TYPE_RAW;
            default -> OracleColumn.TYPE_NUMBER;
        };
    }
}
