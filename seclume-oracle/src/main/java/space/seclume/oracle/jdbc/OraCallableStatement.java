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
import space.seclume.internal.jdbc.ParameterNames;
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

    // ---- parameters by name ------------------------------------------------

    /**
     * The catalog question, asked once per statement.
     *
     * <p>Oracle keeps this in {@code all_arguments} rather than in
     * {@code information_schema}, which it does not have. Three details of
     * that view matter here:
     *
     * <ul>
     *   <li><b>{@code data_level = 0}</b> - a record or collection argument
     *       is listed again, one row per field, at a deeper level. Without
     *       this those fields would be counted as parameters of their
     *       own.</li>
     *   <li><b>{@code position > 0}</b> - position 0 is a function's return
     *       value, which JDBC counts as parameter 1 by itself.</li>
     *   <li><b>{@code subprogram_id}</b> - a package may declare the same
     *       procedure name several times, and it is the pair of object and
     *       subprogram that identifies one of them.</li>
     * </ul>
     */
    private static final String PARAMETER_QUERY = """
            select a.object_id || '.' || a.subprogram_id, a.argument_name, a.position
              from all_arguments a
             where upper(a.object_name) = upper(?)
               and %s
               and a.data_level = 0
               and a.position > 0
             order by a.object_id, a.subprogram_id, a.position""";

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
        String container = null;
        String routine = call.name();
        int dot = routine.lastIndexOf('.');
        if (dot >= 0) {
            container = routine.substring(0, dot);
            routine = routine.substring(dot + 1);
        }
        // A qualified call is pkg.proc far more often than owner.proc, and a
        // stand-alone procedure has no package at all - so the one name in
        // front is allowed to be either.
        String sql = PARAMETER_QUERY.formatted(container == null
                ? "a.package_name is null"
                : "(upper(a.package_name) = upper(?) or upper(a.owner) = upper(?))");
        int arguments = call.parameters() - (call.returnsValue() ? 1 : 0);
        try (java.sql.PreparedStatement ask = connection.prepareStatement(sql)) {
            ask.setString(1, unquoted(routine));
            if (container != null) {
                // Twice, because the driver numbers placeholders by position:
                // one name, asked of the package column and of the owner.
                ask.setString(2, unquoted(container));
                ask.setString(3, unquoted(container));
            }
            try (ResultSet rows = ask.executeQuery()) {
                return ParameterNames.fromCatalog(rows, arguments, call.returnsValue());
            }
        }
    }

    /** A quoted identifier stands for itself; the quotes are not part of the name. */
    private static String unquoted(String identifier) {
        String text = identifier.trim();
        return text.length() > 1 && text.startsWith("\"") && text.endsWith("\"")
                ? text.substring(1, text.length() - 1)
                : text;
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
        checkOpen();
        return space.seclume.internal.jdbc.PlaceholderMetaData.ofCall(call.totalParameters());
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

        boolean[] cursorBinds = new boolean[outputs.size()];
        boolean anyCursor = false;
        for (int i = 0; i < outputs.size(); i++) {
            cursorBinds[i] = registeredTypes.getOrDefault(outputs.get(i), Types.NUMERIC)
                    == Types.REF_CURSOR;
            anyCursor |= cursorBinds[i];
        }
        connection.session().expectReturning(outputs.size(), true,
                anyCursor ? cursorBinds : null);
        run(block(), binds);
        decodeOutputs(lastReturned());
        readCursors();
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
                + "getters - a cursor the procedure opens is one of them: register it with "
                + "registerOutParameter(i, Types.REF_CURSOR) and read it with getObject(i)");
    }

    /**
     * Turns the cursors the call brought back into result sets.
     *
     * <p>They arrive in the order of the output binds that are cursors, which
     * is the order {@link #outputs} holds them in once the non-cursor ones
     * are passed over.
     */
    private void readCursors() throws SQLException {
        java.util.List<space.seclume.oracle.net.TtcResult.Cursor> opened =
                lastAnswer() == null ? java.util.List.of() : lastAnswer().cursors();
        int next = 0;
        for (int index : outputs) {
            if (registeredTypes.getOrDefault(index, Types.NUMERIC) != Types.REF_CURSOR) {
                continue;
            }
            if (next >= opened.size()) {
                values.put(index, null);
                continue;
            }
            var cursor = opened.get(next++);
            values.put(index, cursor.columns().isEmpty()
                    ? null : readCursor(cursor.id(), cursor.columns()));
        }
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
            case Types.BINARY, Types.VARBINARY, Types.LONGVARBINARY, Types.REF_CURSOR -> bytes;
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
            case Types.REF_CURSOR -> OracleColumn.TYPE_CURSOR;
            default -> OracleColumn.TYPE_NUMBER;
        };
    }
}
