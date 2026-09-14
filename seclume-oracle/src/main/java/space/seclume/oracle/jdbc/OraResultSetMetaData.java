package space.seclume.oracle.jdbc;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.List;

import space.seclume.oracle.net.OracleColumn;

/**
 * The column description of a result.
 *
 * <p>Everything here comes out of {@code DESCRIBE_INFO}. What Oracle does not
 * send is the table a column came from, so {@code getTableName} stays empty
 * rather than guessing or slipping in a catalog query behind the caller's
 * back.
 *
 * <p>The scale needs a word: Oracle reports <b>-127</b> for a {@code NUMBER}
 * whose scale was never declared - a computed value, for instance. That is not
 * "no decimal places", and reporting it as 0 would make a caller round where
 * it should not. JDBC has no way to say "undeclared", so 0 is what goes out -
 * and this comment is why.
 */
final class OraResultSetMetaData implements ResultSetMetaData {

    private final List<OracleColumn> columns;

    OraResultSetMetaData(List<OracleColumn> columns) {
        this.columns = columns;
    }

    private OracleColumn column(int index) throws SQLException {
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
        return column(index).sqlType();
    }

    @Override
    public String getColumnTypeName(int index) throws SQLException {
        return column(index).typeName();
    }

    @Override
    public String getColumnClassName(int index) throws SQLException {
        OracleColumn c = column(index);
        if (c.type() == OracleColumn.TYPE_NUMBER) {
            return c.scale() == 0 && c.precision() > 0 && c.precision() <= 9
                    ? "java.lang.Long"
                    : "java.math.BigDecimal";
        }
        return "java.lang.String";
    }

    @Override
    public int getPrecision(int index) throws SQLException {
        OracleColumn c = column(index);
        return c.precision() > 0 ? c.precision() : c.maxSize();
    }

    @Override
    public int getScale(int index) throws SQLException {
        int scale = column(index).scale();
        return scale == OracleColumn.SCALE_UNDECLARED ? 0 : scale;
    }

    @Override
    public int getColumnDisplaySize(int index) throws SQLException {
        return column(index).maxSize();
    }

    @Override
    public boolean isSigned(int index) throws SQLException {
        return column(index).type() == OracleColumn.TYPE_NUMBER;
    }

    @Override
    public int isNullable(int index) throws SQLException {
        return column(index).nullable() ? columnNullable : columnNoNulls;
    }

    @Override
    public boolean isCaseSensitive(int index) throws SQLException {
        // Oracle compares text case-sensitively unless the session says
        // otherwise, and this driver does not change that.
        return column(index).isText();
    }

    @Override
    public boolean isSearchable(int index) throws SQLException {
        column(index);
        return true;
    }

    @Override
    public boolean isCurrency(int index) throws SQLException {
        column(index);
        return false;
    }

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
