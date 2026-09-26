package space.seclume.mysql;

import java.sql.Types;

/**
 * MySQL's column types, as they appear in the column description.
 *
 * <p>The numbers come from {@code mysql_com.h} and have been fixed for decades.
 * They show up twice: in the description of a result and - the same numbers -
 * in the parameters of {@code COM_STMT_EXECUTE}.
 */
public final class MyTypes {

    public static final int DECIMAL = 0x00;
    public static final int TINY = 0x01;
    public static final int SHORT = 0x02;
    public static final int LONG = 0x03;
    public static final int FLOAT = 0x04;
    public static final int DOUBLE = 0x05;
    public static final int NULL = 0x06;
    public static final int TIMESTAMP = 0x07;
    public static final int LONGLONG = 0x08;
    public static final int INT24 = 0x09;
    public static final int DATE = 0x0a;
    public static final int TIME = 0x0b;
    public static final int DATETIME = 0x0c;
    public static final int YEAR = 0x0d;
    public static final int NEWDATE = 0x0e;
    public static final int VARCHAR = 0x0f;
    public static final int BIT = 0x10;
    public static final int JSON = 0xf5;
    public static final int NEWDECIMAL = 0xf6;
    public static final int ENUM = 0xf7;
    public static final int SET = 0xf8;
    public static final int TINY_BLOB = 0xf9;
    public static final int MEDIUM_BLOB = 0xfa;
    public static final int LONG_BLOB = 0xfb;
    public static final int BLOB = 0xfc;
    public static final int VAR_STRING = 0xfd;
    public static final int STRING = 0xfe;
    public static final int GEOMETRY = 0xff;

    /** Column flag: the value is unsigned. */
    public static final int FLAG_UNSIGNED = 0x0020;
    /** Column flag: the column cannot hold NULL. */
    public static final int FLAG_NOT_NULL = 0x0001;
    /** Column flag: binary, so not text - this is how MySQL tells blob from text. */
    public static final int FLAG_BINARY = 0x0080;
    /** Column flag: counts up automatically. */
    public static final int FLAG_AUTO_INCREMENT = 0x0200;
    /** Column flag: part of a primary key. */
    public static final int FLAG_PRIMARY_KEY = 0x0002;

    private MyTypes() {
    }

    /**
     * Whether this column is the way MySQL stores a boolean.
     *
     * <p>MySQL has no boolean type: {@code boolean} is a synonym for
     * {@code tinyint(1)}, and that is what Hibernate, Spring Data and every
     * migration tool write. The wire carries a {@code TINY} whose declared
     * display width is one, which is the only thing that tells it apart from
     * an ordinary {@code tinyint} - so that is what is asked here, and the
     * question is asked in one place because the answer has to be the same for
     * the value, the result metadata and the catalogue.
     *
     * <p>Connector/J calls the switch {@code tinyInt1isBit} and has it on;
     * this driver takes the name and the default from it, because the point of
     * the mapping is that code moving from one to the other keeps working.
     */
    public static boolean isBooleanColumn(int type, long columnLength, boolean tinyInt1isBit) {
        return tinyInt1isBit && type == TINY && columnLength == 1;
    }

    public static int sqlType(int type, int flags) {
        boolean binary = (flags & FLAG_BINARY) != 0;
        return switch (type) {
            case TINY -> Types.TINYINT;
            case SHORT -> Types.SMALLINT;
            // A date, the way Connector/J reports it (its yearIsDateType, on by
            // default): an ORM mapping by type code expects a DATE here.
            case YEAR -> Types.DATE;
            // INTEGER even when unsigned - Connector/J says so, and hands an int
            // unsigned out as a Long all the same.
            case INT24, LONG -> Types.INTEGER;
            case LONGLONG -> Types.BIGINT;
            case FLOAT -> Types.REAL;
            case DOUBLE -> Types.DOUBLE;
            case DECIMAL, NEWDECIMAL -> Types.DECIMAL;
            case DATE, NEWDATE -> Types.DATE;
            case TIME -> Types.TIME;
            case TIMESTAMP, DATETIME -> Types.TIMESTAMP;
            case BIT -> Types.BIT;
            case NULL -> Types.NULL;
            case TINY_BLOB, MEDIUM_BLOB, LONG_BLOB, BLOB ->
                    binary ? Types.LONGVARBINARY : Types.LONGVARCHAR;
            case VARCHAR, VAR_STRING -> binary ? Types.VARBINARY : Types.VARCHAR;
            case STRING -> binary ? Types.BINARY : Types.CHAR;
            case GEOMETRY -> Types.BINARY;
            case JSON -> Types.LONGVARCHAR;
            default -> Types.VARCHAR;
        };
    }

    public static String typeName(int type, int flags) {
        boolean unsigned = (flags & FLAG_UNSIGNED) != 0;
        boolean binary = (flags & FLAG_BINARY) != 0;
        String name = switch (type) {
            case DECIMAL, NEWDECIMAL -> "DECIMAL";
            case TINY -> "TINYINT";
            case SHORT -> "SMALLINT";
            case LONG -> "INT";
            case FLOAT -> "FLOAT";
            case DOUBLE -> "DOUBLE";
            case NULL -> "NULL";
            case TIMESTAMP -> "TIMESTAMP";
            case LONGLONG -> "BIGINT";
            case INT24 -> "MEDIUMINT";
            case DATE, NEWDATE -> "DATE";
            case TIME -> "TIME";
            case DATETIME -> "DATETIME";
            case YEAR -> "YEAR";
            case BIT -> "BIT";
            case JSON -> "JSON";
            case ENUM -> "ENUM";
            case SET -> "SET";
            case TINY_BLOB -> binary ? "TINYBLOB" : "TINYTEXT";
            case MEDIUM_BLOB -> binary ? "MEDIUMBLOB" : "MEDIUMTEXT";
            case LONG_BLOB -> binary ? "LONGBLOB" : "LONGTEXT";
            case BLOB -> binary ? "BLOB" : "TEXT";
            case VARCHAR, VAR_STRING -> binary ? "VARBINARY" : "VARCHAR";
            case STRING -> binary ? "BINARY" : "CHAR";
            case GEOMETRY -> "GEOMETRY";
            default -> "UNKNOWN";
        };
        // The server flags bit and year unsigned too; nobody writes them so.
        return unsigned && type != BIT && type != YEAR && !name.equals("UNKNOWN")
                ? name + " UNSIGNED" : name;
    }

    public static String javaClass(int type, int flags) {
        boolean unsigned = (flags & FLAG_UNSIGNED) != 0;
        boolean binary = (flags & FLAG_BINARY) != 0;
        return switch (type) {
            case TINY, SHORT, INT24 -> "java.lang.Integer";
            case YEAR -> "java.sql.Date";
            case LONG -> unsigned ? "java.lang.Long" : "java.lang.Integer";
            case LONGLONG -> unsigned ? "java.math.BigInteger" : "java.lang.Long";
            case FLOAT -> "java.lang.Float";
            case DOUBLE -> "java.lang.Double";
            case DECIMAL, NEWDECIMAL -> "java.math.BigDecimal";
            case DATE, NEWDATE -> "java.sql.Date";
            case TIME -> "java.sql.Time";
            case TIMESTAMP -> "java.sql.Timestamp";
            case DATETIME -> "java.time.LocalDateTime";
            case TINY_BLOB, MEDIUM_BLOB, LONG_BLOB, BLOB, GEOMETRY ->
                    binary ? "[B" : "java.lang.String";
            case VARCHAR, VAR_STRING, STRING -> binary ? "[B" : "java.lang.String";
            default -> "java.lang.String";
        };
    }

    /** Whether a value of this type has a fixed length in the binary protocol. */
    public static int binaryFixedLength(int type) {
        return switch (type) {
            case TINY -> 1;
            case SHORT, YEAR -> 2;
            case LONG, INT24, FLOAT -> 4;
            case LONGLONG, DOUBLE -> 8;
            default -> -1;
        };
    }
}
