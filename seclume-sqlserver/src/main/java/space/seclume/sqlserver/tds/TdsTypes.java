package space.seclume.sqlserver.tds;

import java.sql.Types;

/**
 * The column types of TDS.
 *
 * <p>SQL Server distinguishes two families that look alike but are framed
 * differently on the wire:
 *
 * <ul>
 *   <li><b>Fixed length</b> ({@link #INT4}, {@link #BIT}, {@link #FLT8} …).
 *       The value is always there and always the same size; there is no length
 *       byte and no way to say NULL.</li>
 *   <li><b>Nullable</b> ({@link #INTN}, {@link #BITN}, {@link #FLTN} …). Each
 *       value carries a length byte in front, and length zero means NULL. The
 *       column description names the maximum size.</li>
 * </ul>
 *
 * <p>That distinction is the reason a row cannot be parsed without the column
 * description: the same eight bytes are a {@code bigint} in one result and a
 * length byte plus seven bytes of something else in the next.
 */
public final class TdsTypes {

    // ---- fixed length ----------------------------------------------------

    public static final int NULLTYPE = 0x1f;
    public static final int INT1 = 0x30;
    public static final int BIT = 0x32;
    public static final int INT2 = 0x34;
    public static final int INT4 = 0x38;
    public static final int DATETIM4 = 0x3a;
    public static final int FLT4 = 0x3b;
    public static final int MONEY = 0x3c;
    public static final int DATETIME = 0x3d;
    public static final int FLT8 = 0x3e;
    public static final int MONEY4 = 0x7a;
    public static final int INT8 = 0x7f;

    // ---- nullable, with a length byte ------------------------------------

    public static final int GUID = 0x24;
    public static final int INTN = 0x26;
    public static final int DECIMAL = 0x37;
    public static final int NUMERIC = 0x3f;
    public static final int BITN = 0x68;
    public static final int DECIMALN = 0x6a;
    public static final int NUMERICN = 0x6c;
    public static final int FLTN = 0x6d;
    public static final int MONEYN = 0x6e;
    public static final int DATETIMN = 0x6f;
    public static final int DATEN = 0x28;
    public static final int TIMEN = 0x29;
    public static final int DATETIME2N = 0x2a;
    public static final int DATETIMEOFFSETN = 0x2b;
    public static final int CHAR = 0x2f;
    public static final int VARCHAR = 0x27;
    public static final int BINARY = 0x2d;
    public static final int VARBINARY = 0x25;

    // ---- long, with a two- or four-byte length ---------------------------

    public static final int BIGVARBINARY = 0xa5;
    public static final int BIGVARCHAR = 0xa7;
    public static final int BIGBINARY = 0xad;
    public static final int BIGCHAR = 0xaf;
    public static final int NVARCHAR = 0xe7;
    public static final int NCHAR = 0xef;
    public static final int XML = 0xf1;
    public static final int TEXT = 0x23;
    public static final int IMAGE = 0x22;
    public static final int NTEXT = 0x63;

    private TdsTypes() {
    }

    /** How many bytes a fixed-length type occupies; -1 if it is not one. */
    public static int fixedLength(int type) {
        return switch (type) {
            case NULLTYPE -> 0;
            case INT1, BIT -> 1;
            case INT2 -> 2;
            case INT4, FLT4, DATETIM4, MONEY4 -> 4;
            case FLT8, MONEY, DATETIME, INT8 -> 8;
            default -> -1;
        };
    }

    /**
     * Whether the type carries a two-byte length instead of a one-byte one.
     *
     * <p>Get this wrong and the row is off by one byte from that column on -
     * and the values after it turn into plausible nonsense rather than an
     * error, which is worse.
     */
    public static boolean hasTwoByteLength(int type) {
        return switch (type) {
            case BIGVARBINARY, BIGVARCHAR, BIGBINARY, BIGCHAR, NVARCHAR, NCHAR -> true;
            default -> false;
        };
    }

    /** Whether the type carries a four-byte length (the large ones). */
    public static boolean hasFourByteLength(int type) {
        return switch (type) {
            case TEXT, IMAGE, NTEXT, XML -> true;
            default -> false;
        };
    }

    /** Whether the value is UTF-16 text rather than bytes. */
    public static boolean isUnicodeText(int type) {
        return switch (type) {
            case NVARCHAR, NCHAR, NTEXT, XML -> true;
            default -> false;
        };
    }

    /** Whether the value is single-byte text. */
    public static boolean isSingleByteText(int type) {
        return switch (type) {
            case CHAR, VARCHAR, BIGCHAR, BIGVARCHAR, TEXT -> true;
            default -> false;
        };
    }

    /** The matching {@link Types} value that JDBC callers expect. */
    public static int sqlType(int type, int size, int scale) {
        return switch (type) {
            case BIT, BITN -> Types.BOOLEAN;
            case INT1 -> Types.TINYINT;
            case INT2 -> Types.SMALLINT;
            case INT4 -> Types.INTEGER;
            case INT8 -> Types.BIGINT;
            case INTN -> switch (size) {
                case 1 -> Types.TINYINT;
                case 2 -> Types.SMALLINT;
                case 4 -> Types.INTEGER;
                default -> Types.BIGINT;
            };
            case FLT4 -> Types.REAL;
            case FLT8 -> Types.DOUBLE;
            case FLTN -> size == 4 ? Types.REAL : Types.DOUBLE;
            case DECIMAL, DECIMALN, NUMERIC, NUMERICN -> Types.DECIMAL;
            case MONEY, MONEY4, MONEYN -> Types.DECIMAL;
            case DATETIME, DATETIM4, DATETIMN, DATETIME2N -> Types.TIMESTAMP;
            case DATETIMEOFFSETN -> Types.TIMESTAMP_WITH_TIMEZONE;
            case DATEN -> Types.DATE;
            case TIMEN -> Types.TIME;
            case GUID -> Types.CHAR;
            case CHAR, BIGCHAR, NCHAR -> Types.CHAR;
            case VARCHAR, BIGVARCHAR, NVARCHAR -> Types.VARCHAR;
            case TEXT, NTEXT -> Types.LONGVARCHAR;
            case XML -> Types.SQLXML;
            case BINARY, BIGBINARY -> Types.BINARY;
            case VARBINARY, BIGVARBINARY -> Types.VARBINARY;
            case IMAGE -> Types.LONGVARBINARY;
            default -> Types.OTHER;
        };
    }

    /** The type name as SQL Server writes it. */
    public static String typeName(int type, int size) {
        return switch (type) {
            case BIT, BITN -> "bit";
            case INT1 -> "tinyint";
            case INT2 -> "smallint";
            case INT4 -> "int";
            case INT8 -> "bigint";
            case INTN -> switch (size) {
                case 1 -> "tinyint";
                case 2 -> "smallint";
                case 4 -> "int";
                default -> "bigint";
            };
            case FLT4 -> "real";
            case FLT8 -> "float";
            case FLTN -> size == 4 ? "real" : "float";
            case DECIMAL, DECIMALN -> "decimal";
            case NUMERIC, NUMERICN -> "numeric";
            case MONEY, MONEY4, MONEYN -> "money";
            case DATETIME, DATETIM4, DATETIMN -> "datetime";
            case DATETIME2N -> "datetime2";
            case DATETIMEOFFSETN -> "datetimeoffset";
            case DATEN -> "date";
            case TIMEN -> "time";
            case GUID -> "uniqueidentifier";
            case CHAR, BIGCHAR -> "char";
            case NCHAR -> "nchar";
            case VARCHAR, BIGVARCHAR -> "varchar";
            case NVARCHAR -> "nvarchar";
            case TEXT -> "text";
            case NTEXT -> "ntext";
            case XML -> "xml";
            case BINARY, BIGBINARY -> "binary";
            case VARBINARY, BIGVARBINARY -> "varbinary";
            case IMAGE -> "image";
            default -> "unknown(0x" + Integer.toHexString(type) + ")";
        };
    }

    /** The Java class {@code getObject} will hand out for this column. */
    public static String javaClass(int type, int size) {
        return switch (type) {
            case BIT, BITN -> "java.lang.Boolean";
            case INT1, INT2, INT4 -> "java.lang.Integer";
            case INT8 -> "java.lang.Long";
            case INTN -> size <= 4 ? "java.lang.Integer" : "java.lang.Long";
            case FLT4 -> "java.lang.Float";
            case FLT8 -> "java.lang.Double";
            case FLTN -> size == 4 ? "java.lang.Float" : "java.lang.Double";
            case DECIMAL, DECIMALN, NUMERIC, NUMERICN, MONEY, MONEY4, MONEYN ->
                    "java.math.BigDecimal";
            case DATETIME, DATETIM4, DATETIMN, DATETIME2N -> "java.sql.Timestamp";
            case DATETIMEOFFSETN -> "java.time.OffsetDateTime";
            case DATEN -> "java.sql.Date";
            case TIMEN -> "java.sql.Time";
            case BINARY, BIGBINARY, VARBINARY, BIGVARBINARY, IMAGE -> "[B";
            default -> "java.lang.String";
        };
    }
}
