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
    private final boolean tinyInt1isBit;

    MyResultSetMetaData(List<MySession.Field> fields, boolean tinyInt1isBit) {
        this.fields = fields;
        this.tinyInt1isBit = tinyInt1isBit;
    }

    /** Whether this column is the tinyint(1) an ORM stores a boolean in. */
    private boolean isBoolean(MySession.Field f) {
        return MyTypes.isBooleanColumn(f.type(), f.columnLength(), tinyInt1isBit);
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
        if (isBoolean(f)) {
            return java.sql.Types.BIT;
        }
        return isLobFamily(f) ? lobSqlType(f) : MyTypes.sqlType(f.type(), f.flags());
    }

    @Override
    public String getColumnTypeName(int column) throws SQLException {
        MySession.Field f = field(column);
        if (isBoolean(f)) {
            return "BIT";
        }
        return isLobFamily(f) ? lobTypeName(f) : MyTypes.typeName(f.type(), f.flags());
    }

    @Override
    public String getColumnClassName(int column) throws SQLException {
        MySession.Field f = field(column);
        return isBoolean(f) ? "java.lang.Boolean" : MyTypes.javaClass(f.type(), f.flags());
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
            int bytesPerCharacter = bytesPerCharacter(f);
            length = length / bytesPerCharacter;
            if (isLobFamily(f)) {
                // Not arithmetic on the wire value. varchar(40) is forty
                // CHARACTERS and arrives as 160 in utf8mb4, so one division
                // gives the forty. text is 65535 BYTES and arrives as 262140,
                // so the same division gives a byte capacity and the
                // characters are 16383 - which is what getPrecision is
                // defined as for character data, and what Connector/J
                // answers. Doing that as a second division worked for three
                // of the four sizes and not for longtext, whose capacity
                // times four does not fit in the four bytes the field has:
                // the server sends the byte count itself and the second
                // division then took a factor of four off the answer. So the
                // capacity is identified instead, and divided once.
                length = lobCapacity(f) / bytesPerCharacter;
            }
        } else if (isDecimal(f) && length > 0) {
            // The field length of decimal(20,6) is 22: twenty digits, the
            // decimal point and the sign. getPrecision is the twenty.
            length -= (f.decimals() > 0 ? 1 : 0) + (f.unsigned() ? 0 : 1);
        } else if (isSignedInteger(f) && length > 0) {
            // MySQL sends the display width, which has room for the minus
            // sign: 11 for int, 20 for bigint. getPrecision is the maximum
            // number of digits - 10 and 19 - and that is what Connector/J
            // reports. An unsigned column has no sign to make room for and
            // keeps its width.
            // Never below one: tinyint(1) has a display width of 1, and a
            // column that can hold a digit has a precision of at least one
            // digit. Subtracting blindly reported 0, which is what this
            // guard is here to have caught.
            length = Math.max(1, length - 1);
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

    /** Fixed-point, where the length also counts the point and the sign. */
    private static boolean isDecimal(MySession.Field f) {
        return f.type() == MyTypes.DECIMAL || f.type() == MyTypes.NEWDECIMAL;
    }

    /** A whole-number column that reserves a character for its sign. */
    private static boolean isSignedInteger(MySession.Field f) {
        if (f.unsigned()) {
            return false;
        }
        return switch (f.type()) {
            case MyTypes.TINY, MyTypes.SHORT, MyTypes.INT24, MyTypes.LONG,
                 MyTypes.LONGLONG -> true;
            default -> false;
        };
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

    /** How many bytes one character of this column takes at most. */
    private static int bytesPerCharacter(MySession.Field field) {
        return switch (field.charset()) {
            case 45, 46, 255 -> 4;          // utf8mb4
            case 33, 83, 192 -> 3;          // utf8mb3
            default -> 1;
        };
    }

    /**
     * The size class of a text or blob column, as a type name.
     *
     * <p>MySQL sends <b>one</b> type code for all four sizes - a
     * {@code mediumtext} and a {@code tinytext} arrive as the same 252 - so the
     * only thing that tells them apart on the wire is the declared capacity.
     * The driver reported {@code TEXT} for every one of them, where
     * Connector/J and the catalogue both name the size; a dialect that matches
     * on the type name sees the wrong column. Found beside the precision fix,
     * not by a test: the differential corpus has a {@code text} column and no
     * {@code mediumtext}, which is exactly how a gap like this survives.
     */
    private static String lobTypeName(MySession.Field field) {
        boolean binary = field.charset() == 63;
        long capacity = lobCapacity(field);
        if (capacity == 255L) {
            return binary ? "TINYBLOB" : "TINYTEXT";
        }
        if (capacity == 65535L) {
            return binary ? "BLOB" : "TEXT";
        }
        if (capacity == 16777215L) {
            return binary ? "MEDIUMBLOB" : "MEDIUMTEXT";
        }
        return binary ? "LONGBLOB" : "LONGTEXT";
    }

    /**
     * Which of the four sizes this column was declared as, in <b>bytes</b>.
     *
     * <p>Everything about this family follows from that one number - the type
     * name, the JDBC type code and the precision - so it is worked out once.
     * The declared capacity is a round figure (255, 65535, 16777215,
     * 4294967295) and what arrives on the wire is that capacity in bytes
     * multiplied by the character width, except for {@code longtext}, where
     * the product does not fit in the four bytes the field has and the server
     * sends the byte count itself. Deriving the capacity and working from it
     * avoids that exception entirely; arithmetic on the wire value does not,
     * which is what the old precision was wrong about.
     */
    private static long lobCapacity(MySession.Field field) {
        long bytes = field.columnLength() / bytesPerCharacter(field);
        if (bytes <= 255) {
            return 255L;
        }
        if (bytes <= 65535) {
            return 65535L;
        }
        if (bytes <= 16777215) {
            return 16777215L;
        }
        return 4294967295L;
    }

    /**
     * The JDBC type of a text or blob column, which also depends on the size.
     *
     * <p>Connector/J answers {@code VARCHAR} for {@code tinytext} and
     * {@code VARBINARY} for {@code tinyblob}, and the long forms for the other
     * three. That is not an oddity to be matched for its own sake: 255 bytes
     * is not long data, and a dialect or an ORM that branches on
     * {@code LONGVARCHAR} treats such a column as a stream it has to be
     * careful with. Found by putting all four sizes in the differential
     * corpus, where previously only {@code text} and {@code blob} were.
     */
    private static int lobSqlType(MySession.Field field) {
        boolean binary = field.charset() == 63;
        if (lobCapacity(field) == 255L) {
            return binary ? java.sql.Types.VARBINARY : java.sql.Types.VARCHAR;
        }
        return binary ? java.sql.Types.LONGVARBINARY : java.sql.Types.LONGVARCHAR;
    }

    /**
     * The types whose declared size is a byte capacity rather than a character
     * count - {@code tinytext} to {@code longtext}, and the blobs beside them.
     */
    private static boolean isLobFamily(MySession.Field field) {
        return switch (field.type()) {
            case MyTypes.BLOB, MyTypes.TINY_BLOB, MyTypes.MEDIUM_BLOB, MyTypes.LONG_BLOB -> true;
            default -> false;
        };
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
