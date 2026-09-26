package space.seclume.sqlserver.jdbc;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.List;

import space.seclume.sqlserver.tds.TdsColumn;
import space.seclume.sqlserver.tds.TdsTypes;

/**
 * The column description of a result.
 *
 * <p>Everything here comes out of {@code COLMETADATA} - name, type, size,
 * precision, scale, nullable. What TDS does not send is the table a column
 * came from: that would need the {@code fColMetaData} extension with the table
 * name per column, which the server only fills in for a browse query. Rather
 * than smuggle in a catalog query behind the caller's back, the answers to
 * {@code getTableName} and {@code getSchemaName} stay empty - the honest
 * answer to "I do not know".
 */
final class TdsResultSetMetaData implements ResultSetMetaData {

    private final List<TdsColumn> columns;

    TdsResultSetMetaData(List<TdsColumn> columns) {
        this.columns = columns;
    }

    private TdsColumn column(int index) throws SQLException {
        if (index < 1 || index > columns.size()) {
            throw new SQLException("column " + index + " is out of range 1.." + columns.size());
        }
        return columns.get(index - 1);
    }

    @Override
    public int getColumnCount() {
        return columns.size();
    }

    @Override
    public String getColumnLabel(int index) throws SQLException {
        return column(index).name();
    }

    @Override
    public String getColumnName(int index) throws SQLException {
        return column(index).name();
    }

    @Override
    public int getColumnType(int index) throws SQLException {
        TdsColumn c = column(index);
        return TdsTypes.sqlType(c.type(), c.size(), c.scale());
    }

    @Override
    public String getColumnTypeName(int index) throws SQLException {
        TdsColumn c = column(index);
        return c.typeName() != null ? c.typeName() : TdsTypes.typeName(c.type(), c.size());
    }

    @Override
    public String getColumnClassName(int index) throws SQLException {
        TdsColumn c = column(index);
        return TdsTypes.javaClass(c.type(), c.size());
    }

    /**
     * For {@code decimal} the precision is the digit count the server sent; for
     * text it is the character count, and there the size is in bytes - UTF-16
     * takes two per character, so it gets halved.
     */
    @Override
    public int getPrecision(int index) throws SQLException {
        TdsColumn c = column(index);
        if (c.precision() > 0) {
            return c.precision();
        }
        if (c.size() == TdsColumn.MAX_SIZE) {
            // varchar(max): the server declares no length at all.
            return 0;
        }
        // Digits before bytes. The size is the right answer only for the
        // text and binary types, where the length is the precision; for a
        // number or a date it is the wire width and has nothing to do with
        // what getPrecision means.
        int digits = TdsTypes.precisionOf(c.type(), c.size(), c.scale());
        if (digits > 0) {
            return digits;
        }
        return TdsTypes.isUnicodeText(c.type()) ? c.size() / 2 : c.size();
    }

    @Override
    public int getScale(int index) throws SQLException {
        TdsColumn c = column(index);
        // money and datetime carry a scale the wire never mentions - four
        // places and three. Reporting 0 for them said the values were whole
        // numbers, which they are not.
        int declared = c.scale();
        return declared > 0 ? declared : TdsTypes.scaleOf(c.type(), c.size());
    }

    @Override
    public int getColumnDisplaySize(int index) throws SQLException {
        return getPrecision(index);
    }

    @Override
    public boolean isSigned(int index) throws SQLException {
        return switch (column(index).type()) {
            case TdsTypes.INT2, TdsTypes.INT4, TdsTypes.INT8, TdsTypes.INTN, TdsTypes.FLT4,
                 TdsTypes.FLT8, TdsTypes.FLTN, TdsTypes.DECIMAL, TdsTypes.DECIMALN,
                 TdsTypes.NUMERIC, TdsTypes.NUMERICN, TdsTypes.MONEY, TdsTypes.MONEY4,
                 TdsTypes.MONEYN -> true;
            // tinyint is the odd one out: in SQL Server it is 0..255.
            default -> false;
        };
    }

    @Override
    public int isNullable(int index) throws SQLException {
        return column(index).nullable() ? columnNullable : columnNoNulls;
    }

    /**
     * The collation would say it, and this driver skips the collation. Rather
     * than guess, it answers with the SQL Server default - and the open point
     * is recorded in {@code PROVENANCE.md}.
     */
    @Override
    public boolean isCaseSensitive(int index) throws SQLException {
        column(index);
        return false;
    }

    @Override
    public boolean isSearchable(int index) throws SQLException {
        column(index);
        return true;
    }

    @Override
    public boolean isCurrency(int index) throws SQLException {
        return switch (column(index).type()) {
            case TdsTypes.MONEY, TdsTypes.MONEY4, TdsTypes.MONEYN -> true;
            default -> false;
        };
    }

    /**
     * TDS marks an identity column in the column flags, but only from the
     * server's own browse mode - which this driver does not switch on.
     */
    @Override
    public boolean isAutoIncrement(int index) throws SQLException {
        column(index);
        return false;
    }

    @Override
    public boolean isReadOnly(int index) throws SQLException {
        column(index);
        return true;
    }

    @Override
    public boolean isWritable(int index) throws SQLException {
        column(index);
        return false;
    }

    @Override
    public boolean isDefinitelyWritable(int index) throws SQLException {
        column(index);
        return false;
    }

    @Override
    public String getTableName(int index) throws SQLException {
        column(index);
        return "";
    }

    @Override
    public String getSchemaName(int index) throws SQLException {
        column(index);
        return "";
    }

    @Override
    public String getCatalogName(int index) throws SQLException {
        column(index);
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
