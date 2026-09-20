package space.seclume.internal.jdbc;

import java.math.BigDecimal;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;

/**
 * A {@code ResultSet} over rows that are already in memory.
 *
 * <p>There is one place JDBC insists on a result set that no server produced:
 * {@link java.sql.Array#getResultSet()}, which hands back the elements of an
 * array as a two-column result. Building that out of a protocol result would
 * mean inventing a row description and a wire buffer for data that is already
 * decoded, so this takes the short way instead.
 *
 * <p>It is deliberately plain - no fetching, no release, no statement behind
 * it - and it is not a place to collect results that a server could have sent.
 * Anything that comes off the wire belongs in the driver's own result set,
 * where it stays off the heap for as long as it can.
 */
public final class ListResultSet extends ReadOnlyResultSet {

    private final String[] names;
    private final int[] sqlTypes;
    private final String[] typeNames;
    private final List<Object[]> rows;
    private Object[] current;

    public ListResultSet(String[] names, int[] sqlTypes, String[] typeNames, List<Object[]> rows) {
        super(null);
        this.names = names;
        this.sqlTypes = sqlTypes;
        this.typeNames = typeNames;
        this.rows = rows;
    }

    @Override
    protected int rowCount() {
        return rows.size();
    }

    @Override
    protected int columnCount() {
        return names.length;
    }

    @Override
    protected void moveTo(int row) {
        current = rows.get(row);
    }

    @Override
    protected boolean isNullAt(int column) {
        return current[column] == null;
    }

    @Override
    protected String stringAt(int column) {
        return String.valueOf(current[column]);
    }

    @Override
    protected long longAt(int column) throws SQLException {
        Object value = current[column];
        if (value instanceof Number number) {
            return number.longValue();
        }
        try {
            return Long.parseLong(String.valueOf(value));
        } catch (NumberFormatException notANumber) {
            throw new SQLException("column " + (column + 1) + " is not an integer", "22018",
                    notANumber);
        }
    }

    @Override
    protected double doubleAt(int column) throws SQLException {
        Object value = current[column];
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        try {
            return Double.parseDouble(String.valueOf(value));
        } catch (NumberFormatException notANumber) {
            throw new SQLException("column " + (column + 1) + " is not a number", "22018",
                    notANumber);
        }
    }

    @Override
    protected byte[] bytesAt(int column) throws SQLException {
        Object value = current[column];
        if (value instanceof byte[] bytes) {
            return bytes;
        }
        throw new SQLException("column " + (column + 1) + " is not binary", "22018");
    }

    @Override
    protected boolean booleanAt(int column) {
        Object value = current[column];
        if (value instanceof Boolean flag) {
            return flag;
        }
        if (value instanceof Number number) {
            return number.longValue() != 0;
        }
        String text = String.valueOf(value);
        return text.equalsIgnoreCase("t") || text.equalsIgnoreCase("true")
                || text.equals("1") || text.equalsIgnoreCase("y");
    }

    @Override
    protected Object objectAt(int column) {
        return current[column];
    }

    @Override
    protected int columnIndexOf(String label) {
        for (int i = 0; i < names.length; i++) {
            if (names[i].equalsIgnoreCase(label)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    protected ResultSetMetaData metaData() {
        return new Meta();
    }

    @Override
    protected void release() {
    }

    /** As much metadata as rows without a server can honestly carry. */
    private final class Meta implements ResultSetMetaData {

        @Override
        public int getColumnCount() {
            return names.length;
        }

        @Override
        public String getColumnName(int column) {
            return names[column - 1];
        }

        @Override
        public String getColumnLabel(int column) {
            return names[column - 1];
        }

        @Override
        public int getColumnType(int column) {
            return sqlTypes[column - 1];
        }

        @Override
        public String getColumnTypeName(int column) {
            return typeNames[column - 1];
        }

        @Override
        public String getColumnClassName(int column) {
            return switch (sqlTypes[column - 1]) {
                case Types.BIGINT, Types.INTEGER -> Long.class.getName();
                case Types.DOUBLE, Types.REAL -> Double.class.getName();
                case Types.NUMERIC, Types.DECIMAL -> BigDecimal.class.getName();
                case Types.BOOLEAN -> Boolean.class.getName();
                case Types.BINARY, Types.VARBINARY -> "[B";
                default -> Object.class.getName();
            };
        }

        @Override
        public int isNullable(int column) {
            return columnNullable;
        }

        @Override
        public boolean isSigned(int column) {
            return switch (sqlTypes[column - 1]) {
                case Types.BIGINT, Types.INTEGER, Types.SMALLINT, Types.DOUBLE, Types.REAL,
                     Types.NUMERIC, Types.DECIMAL -> true;
                default -> false;
            };
        }

        @Override
        public int getColumnDisplaySize(int column) {
            return 0;
        }

        @Override
        public int getPrecision(int column) {
            return 0;
        }

        @Override
        public int getScale(int column) {
            return 0;
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
        public boolean isAutoIncrement(int column) {
            return false;
        }

        @Override
        public boolean isCaseSensitive(int column) {
            return true;
        }

        @Override
        public boolean isSearchable(int column) {
            return false;
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
        public <T> T unwrap(Class<T> iface) throws SQLException {
            if (iface.isInstance(this)) {
                return iface.cast(this);
            }
            throw new SQLException("not a wrapper for " + iface.getName());
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return iface.isInstance(this);
        }
    }
}
