package space.seclume.mysql.jdbc;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.List;

import space.seclume.mysql.MySession;
import space.seclume.mysql.MyTypes;

/**
 * The column description of a result.
 *
 * <p>MySQL is more forthcoming here than PostgreSQL: the description contains
 * schema, table, original name and the flag bits - so also whether a column is
 * {@code NOT NULL} and whether it counts up. This driver can therefore answer
 * that honestly without slipping in a catalog query.
 */
final class MyResultSetMetaData implements ResultSetMetaData {

    private final List<MySession.Field> fields;

    MyResultSetMetaData(List<MySession.Field> fields) {
        this.fields = fields;
    }

    private MySession.Field field(int column) throws SQLException {
        if (column < 1 || column > fields.size()) {
            throw new SQLException("column " + column + " is out of range 1.." + fields.size());
        }
        return fields.get(column - 1);
    }

    @Override
    public int getColumnCount() {
        return fields.size();
    }

    @Override
    public String getColumnLabel(int column) throws SQLException {
        return field(column).name();
    }

    @Override
    public String getColumnName(int column) throws SQLException {
        MySession.Field f = field(column);
        return f.originalName().isEmpty() ? f.name() : f.originalName();
    }

    @Override
    public int getColumnType(int column) throws SQLException {
        MySession.Field f = field(column);
        return MyTypes.sqlType(f.type(), f.flags());
    }

    @Override
    public String getColumnTypeName(int column) throws SQLException {
        MySession.Field f = field(column);
        return MyTypes.typeName(f.type(), f.flags());
    }

    @Override
    public String getColumnClassName(int column) throws SQLException {
        MySession.Field f = field(column);
        return MyTypes.javaClass(f.type(), f.flags());
    }

    /**
     * The column length arrives in bytes; with {@code utf8mb4} that is up to
     * four per character. For a text column the character count is what is
     * meant, so it gets divided - otherwise {@code varchar(40)} would report a
     * precision of 160.
     */
    @Override
    public int getPrecision(int column) throws SQLException {
        MySession.Field f = field(column);
        long length = f.columnLength();
        if (isText(f)) {
            int bytesPerCharacter = switch (f.charset()) {
                case 45, 46, 255 -> 4;      // utf8mb4
                case 33, 83, 192 -> 3;      // utf8mb3
                default -> 1;
            };
            length = length / bytesPerCharacter;
        }
        return (int) Math.min(length, Integer.MAX_VALUE);
    }

    @Override
    public int getScale(int column) throws SQLException {
        MySession.Field f = field(column);
        // 0x1f means "no fixed number of digits" - float and double report that.
        return f.decimals() == 0x1f ? 0 : f.decimals();
    }

    @Override
    public int getColumnDisplaySize(int column) throws SQLException {
        return getPrecision(column);
    }

    @Override
    public boolean isSigned(int column) throws SQLException {
        MySession.Field f = field(column);
        return switch (f.type()) {
            case MyTypes.TINY, MyTypes.SHORT, MyTypes.INT24, MyTypes.LONG, MyTypes.LONGLONG,
                 MyTypes.FLOAT, MyTypes.DOUBLE, MyTypes.DECIMAL, MyTypes.NEWDECIMAL ->
                    !f.unsigned();
            default -> false;
        };
    }

    @Override
    public int isNullable(int column) throws SQLException {
        return field(column).nullable() ? columnNullable : columnNoNulls;
    }

    @Override
    public boolean isCaseSensitive(int column) throws SQLException {
        MySession.Field f = field(column);
        // A binary character set (63) compares byte for byte; the usual _ci
        // collations do not.
        return f.binary() || f.charset() == 63;
    }

    @Override
    public boolean isSearchable(int column) throws SQLException {
        field(column);
        return true;
    }

    @Override
    public boolean isCurrency(int column) throws SQLException {
        field(column);
        return false;
    }

    @Override
    public boolean isAutoIncrement(int column) throws SQLException {
        return (field(column).flags() & MyTypes.FLAG_AUTO_INCREMENT) != 0;
    }

    @Override
    public boolean isReadOnly(int column) throws SQLException {
        // Only computed columns have no table - those really are read-only.
        return field(column).table().isEmpty();
    }

    @Override
    public boolean isWritable(int column) throws SQLException {
        return !isReadOnly(column);
    }

    @Override
    public boolean isDefinitelyWritable(int column) throws SQLException {
        field(column);
        return false;
    }

    @Override
    public String getTableName(int column) throws SQLException {
        return field(column).table();
    }

    @Override
    public String getSchemaName(int column) throws SQLException {
        return field(column).schema();
    }

    /** MySQL calls the database the "catalog"; there is no schema below it. */
    @Override
    public String getCatalogName(int column) throws SQLException {
        return field(column).schema();
    }

    private static boolean isText(MySession.Field field) {
        return switch (field.type()) {
            case MyTypes.VARCHAR, MyTypes.VAR_STRING, MyTypes.STRING, MyTypes.BLOB,
                 MyTypes.TINY_BLOB, MyTypes.MEDIUM_BLOB, MyTypes.LONG_BLOB, MyTypes.JSON,
                 MyTypes.ENUM, MyTypes.SET -> true;
            default -> false;
        };
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
