package space.seclume.r2dbc;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;

import io.r2dbc.spi.ColumnMetadata;
import io.r2dbc.spi.Nullability;
import io.r2dbc.spi.R2dbcType;
import io.r2dbc.spi.RowMetadata;
import io.r2dbc.spi.Type;

/** The columns of a result, read once from the JDBC metadata. */
final class SeclumeRowMetadata implements RowMetadata {

    /** One column: its name, its R2DBC type, its precision and scale. */
    record Column(String getName, Type getType, Class<?> javaType, Integer getPrecision,
                  Integer getScale, Nullability getNullability, String nativeType)
            implements ColumnMetadata {

        @Override
        public Class<?> getJavaType() {
            return javaType;
        }

        @Override
        public Object getNativeTypeMetadata() {
            return nativeType;
        }
    }

    private final List<Column> columns;

    private SeclumeRowMetadata(List<Column> columns) {
        this.columns = List.copyOf(columns);
    }

    static SeclumeRowMetadata of(ResultSetMetaData jdbc) throws SQLException {
        List<Column> columns = new ArrayList<>();
        for (int i = 1; i <= jdbc.getColumnCount(); i++) {
            Type type = r2dbcType(jdbc.getColumnType(i), jdbc.getColumnTypeName(i));
            Class<?> javaType = type.getJavaType();
            int nullable = jdbc.isNullable(i);
            columns.add(new Column(jdbc.getColumnLabel(i), type, javaType,
                    positive(jdbc.getPrecision(i)), positive(jdbc.getScale(i)),
                    nullable == ResultSetMetaData.columnNoNulls ? Nullability.NON_NULL
                            : nullable == ResultSetMetaData.columnNullable ? Nullability.NULLABLE
                            : Nullability.UNKNOWN,
                    jdbc.getColumnTypeName(i)));
        }
        return new SeclumeRowMetadata(columns);
    }

    private static Integer positive(int value) {
        return value > 0 ? value : null;
    }

    int size() {
        return columns.size();
    }

    /** The 0-based index of a column by name, case-insensitive as R2DBC asks. */
    int indexOf(String name) {
        for (int i = 0; i < columns.size(); i++) {
            if (columns.get(i).getName().equalsIgnoreCase(name)) {
                return i;
            }
        }
        throw new NoSuchElementException("no column named '" + name + "' - the columns are "
                + columns.stream().map(Column::getName).toList());
    }

    @Override
    public ColumnMetadata getColumnMetadata(int index) {
        if (index < 0 || index >= columns.size()) {
            throw new IndexOutOfBoundsException("column " + index + " of " + columns.size());
        }
        return columns.get(index);
    }

    @Override
    public ColumnMetadata getColumnMetadata(String name) {
        return columns.get(indexOf(name));
    }

    @Override
    public List<? extends ColumnMetadata> getColumnMetadatas() {
        return columns;
    }

    @Override
    public boolean contains(String name) {
        String wanted = name.toLowerCase(Locale.ROOT);
        return columns.stream().anyMatch(c -> c.getName().toLowerCase(Locale.ROOT).equals(wanted));
    }

    /** A type R2DBC has no name for - json, uuid, an array: its database name, read as Object. */
    private record Other(String getName) implements Type {
        @Override
        public Class<?> getJavaType() {
            return Object.class;
        }
    }

    private static Type r2dbcType(int jdbcType, String nativeName) {
        return switch (jdbcType) {
            case Types.BOOLEAN, Types.BIT -> R2dbcType.BOOLEAN;
            case Types.TINYINT -> R2dbcType.TINYINT;
            case Types.SMALLINT -> R2dbcType.SMALLINT;
            case Types.INTEGER -> R2dbcType.INTEGER;
            case Types.BIGINT -> R2dbcType.BIGINT;
            case Types.REAL -> R2dbcType.REAL;
            case Types.FLOAT, Types.DOUBLE -> R2dbcType.DOUBLE;
            case Types.NUMERIC -> R2dbcType.NUMERIC;
            case Types.DECIMAL -> R2dbcType.DECIMAL;
            case Types.CHAR -> R2dbcType.CHAR;
            case Types.NCHAR -> R2dbcType.NCHAR;
            case Types.NVARCHAR, Types.LONGNVARCHAR -> R2dbcType.NVARCHAR;
            case Types.CLOB -> R2dbcType.CLOB;
            case Types.NCLOB -> R2dbcType.NCLOB;
            case Types.BINARY -> R2dbcType.BINARY;
            case Types.VARBINARY, Types.LONGVARBINARY -> R2dbcType.VARBINARY;
            case Types.BLOB -> R2dbcType.BLOB;
            case Types.DATE -> R2dbcType.DATE;
            case Types.TIME -> R2dbcType.TIME;
            case Types.TIME_WITH_TIMEZONE -> R2dbcType.TIME_WITH_TIME_ZONE;
            case Types.TIMESTAMP -> R2dbcType.TIMESTAMP;
            case Types.TIMESTAMP_WITH_TIMEZONE -> R2dbcType.TIMESTAMP_WITH_TIME_ZONE;
            case Types.VARCHAR, Types.LONGVARCHAR -> R2dbcType.VARCHAR;
            default -> new Other(nativeName);
        };
    }
}
