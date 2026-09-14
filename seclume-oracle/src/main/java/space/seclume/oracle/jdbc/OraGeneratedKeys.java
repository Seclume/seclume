package space.seclume.oracle.jdbc;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.List;

import space.seclume.internal.jdbc.ReadOnlyResultSet;
import space.seclume.oracle.net.OracleNumber;

/**
 * The keys an {@code insert ... returning ... into} wrote back.
 *
 * <p>A result set of its own, and small on purpose: what comes back are a
 * handful of numbers, not a query result. Building it out of a native block
 * would mean inventing column descriptions the server never sent - here the
 * shape is known because the driver chose the {@code returning} clause itself.
 */
final class OraGeneratedKeys extends ReadOnlyResultSet {

    private final List<String> names;
    private final List<byte[]> values;
    private int row = -1;

    OraGeneratedKeys(Statement statement, List<String> names, List<byte[]> values) {
        super(statement);
        this.names = List.copyOf(names);
        this.values = List.copyOf(values);
    }

    @Override
    protected int rowCount() {
        return values.isEmpty() ? 0 : 1;
    }

    @Override
    protected int columnCount() {
        return values.size();
    }

    @Override
    protected void moveTo(int row) {
        this.row = row;
    }

    @Override
    protected boolean isNullAt(int column) {
        return at(column).length == 0;
    }

    @Override
    protected String stringAt(int column) throws SQLException {
        return String.valueOf(longAt(column));
    }

    @Override
    protected long longAt(int column) throws SQLException {
        byte[] bytes = at(column);
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            return OracleNumber.toLong(copy(arena, bytes), 0, bytes.length);
        }
    }

    @Override
    protected double doubleAt(int column) throws SQLException {
        byte[] bytes = at(column);
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            return OracleNumber.toDouble(copy(arena, bytes), 0, bytes.length);
        }
    }

    /** The bytes where the number reader expects them - off the heap. */
    private static java.lang.foreign.MemorySegment copy(java.lang.foreign.Arena arena,
                                                        byte[] bytes) {
        java.lang.foreign.MemorySegment target = arena.allocate(Math.max(bytes.length, 1));
        java.lang.foreign.MemorySegment.copy(bytes, 0, target,
                java.lang.foreign.ValueLayout.JAVA_BYTE, 0, bytes.length);
        return target;
    }

    @Override
    protected byte[] bytesAt(int column) {
        return at(column).clone(); // seclume-allow: a generated key, payload
    }

    @Override
    protected boolean booleanAt(int column) throws SQLException {
        return longAt(column) != 0;
    }

    @Override
    protected Object objectAt(int column) throws SQLException {
        return longAt(column);
    }

    @Override
    protected int columnIndexOf(String label) {
        for (int i = 0; i < names.size(); i++) {
            if (names.get(i).equalsIgnoreCase(label)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    protected ResultSetMetaData metaData() {
        return new Meta(names);
    }

    @Override
    protected void release() {
        row = -1;
    }

    private byte[] at(int column) {
        if (row != 0 || column < 0 || column >= values.size()) {
            return new byte[0]; // seclume-allow: nothing there, and no secret either
        }
        return values.get(column);
    }

    /** Just enough for {@code getMetaData} on a key set: names and a type. */
    private record Meta(List<String> names) implements ResultSetMetaData {

        @Override
        public int getColumnCount() {
            return names.size();
        }

        @Override
        public String getColumnLabel(int column) {
            return names.get(column - 1);
        }

        @Override
        public String getColumnName(int column) {
            return names.get(column - 1);
        }

        @Override
        public int getColumnType(int column) {
            return Types.NUMERIC;
        }

        @Override
        public String getColumnTypeName(int column) {
            return "NUMBER";
        }

        @Override
        public String getColumnClassName(int column) {
            return Long.class.getName();
        }

        @Override
        public int isNullable(int column) {
            return columnNoNulls;
        }

        @Override
        public boolean isSigned(int column) {
            return true;
        }

        @Override
        public int getColumnDisplaySize(int column) {
            return 22;
        }

        @Override
        public int getPrecision(int column) {
            return 38;
        }

        @Override
        public int getScale(int column) {
            return 0;
        }

        @Override
        public boolean isAutoIncrement(int column) {
            return true;
        }

        @Override
        public boolean isCaseSensitive(int column) {
            return false;
        }

        @Override
        public boolean isSearchable(int column) {
            return true;
        }

        @Override
        public boolean isCurrency(int column) {
            return false;
        }

        @Override
        public boolean isReadOnly(int column) {
            return true;
        }

        @Override
        public boolean isWritable(int column) {
            return false;
        }

        @Override
        public boolean isDefinitelyWritable(int column) {
            return false;
        }

        @Override
        public String getSchemaName(int column) {
            return "";
        }

        @Override
        public String getTableName(int column) {
            return "";
        }

        @Override
        public String getCatalogName(int column) {
            return "";
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            throw new SQLException("this metadata is not a wrapper for " + iface.getName());
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return false;
        }
    }
}
