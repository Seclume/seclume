package space.seclume.postgresql.jdbc;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.List;

import space.seclume.postgresql.PgSession;

/**
 * The column description of a result.
 *
 * <p>Everything here comes from the server's {@code RowDescription}, that is
 * from exactly one message that was read during execution anyway. What that
 * message does not contain - whether a column is {@code NOT NULL}, what the
 * schema is called, whether it counts up automatically - would cost an extra
 * catalog query per result. This driver does not do that: it says
 * {@code columnNullableUnknown} and empty names instead of hiding a query
 * nobody ordered.
 */
final class PgResultSetMetaData implements ResultSetMetaData {

    private final List<PgSession.Field> fields;

    PgResultSetMetaData(List<PgSession.Field> fields) {
        this.fields = fields;
    }

    private PgSession.Field field(int column) throws SQLException {
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
        return field(column).name();
    }

    @Override
    public int getColumnType(int column) throws SQLException {
        return PgOids.sqlType(field(column).typeOid());
    }

    @Override
    public String getColumnTypeName(int column) throws SQLException {
        return PgOids.typeName(field(column).typeOid());
    }

    @Override
    public String getColumnClassName(int column) throws SQLException {
        return PgOids.javaClass(field(column).typeOid());
    }

    @Override
    public int getPrecision(int column) throws SQLException {
        PgSession.Field f = field(column);
        return PgOids.precision(f.typeOid(), f.typeModifier());
    }

    @Override
    public int getScale(int column) throws SQLException {
        PgSession.Field f = field(column);
        return PgOids.scale(f.typeOid(), f.typeModifier());
    }

    @Override
    public int getColumnDisplaySize(int column) throws SQLException {
        int precision = getPrecision(column);
        return precision > 0 ? precision : Integer.MAX_VALUE;
    }

    @Override
    public boolean isSigned(int column) throws SQLException {
        return PgOids.isSigned(field(column).typeOid());
    }

    /**
     * In the {@code RowDescription} the server says nothing about
     * {@code NOT NULL}. A "no" would be a guess, a "yes" just as much - so
     * {@code unknown}, which is exactly what JDBC provides for this.
     */
    @Override
    public int isNullable(int column) throws SQLException {
        field(column);
        return columnNullableUnknown;
    }

    @Override
    public boolean isCaseSensitive(int column) throws SQLException {
        return switch (field(column).typeOid()) {
            case PgOids.TEXT, PgOids.VARCHAR, PgOids.BPCHAR, PgOids.CHAR, PgOids.NAME -> true;
            default -> false;
        };
    }

    @Override
    public boolean isSearchable(int column) throws SQLException {
        field(column);
        return true;
    }

    @Override
    public boolean isCurrency(int column) throws SQLException {
        // money (OID 790) is deliberately not treated separately: the type
        // hangs off lc_monetary and cannot be read reliably.
        field(column);
        return false;
    }

    @Override
    public boolean isAutoIncrement(int column) throws SQLException {
        // Would be in pg_attrdef - a catalog query this result did not
        // order.
        field(column);
        return false;
    }

    @Override
    public boolean isReadOnly(int column) throws SQLException {
        field(column);
        return true;
    }

    @Override
    public boolean isWritable(int column) throws SQLException {
        field(column);
        return false;
    }

    @Override
    public boolean isDefinitelyWritable(int column) throws SQLException {
        field(column);
        return false;
    }

    /** The {@code RowDescription} names the table only as an OID, not by name. */
    @Override
    public String getTableName(int column) throws SQLException {
        field(column);
        return "";
    }

    @Override
    public String getSchemaName(int column) throws SQLException {
        field(column);
        return "";
    }

    @Override
    public String getCatalogName(int column) throws SQLException {
        field(column);
        return "";
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
